//! Join tokens (ADR 0059): reusable until they expire or are revoked, `<id>.<secret>` as
//! kubeadm's bootstrap tokens are; the registry keeps the id and a hash of the secret, never the
//! secret.

use super::*;
use sha2::{Digest, Sha256};

/// How long a token lasts when none is asked (kubeadm's default), and the longest life a finite
/// ttl can ask for; longer is a token that never expires (a ttl of 0).
pub const DEFAULT_TTL: Duration = Duration::hours(24);
pub const MAX_TTL: Duration = Duration::days(3650);
/// A token that ended (revoked or expired) is kept this long, with its uses, for the audit, then
/// dropped by the next mint.
const KEEP_ENDED: Duration = Duration::days(30);

/// A join token as the registry keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinTokenRec {
    pub id: String,
    /// SHA-256 of the secret, hex. The secret has 128 random bits, so a fast hash is enough:
    /// there is nothing to guess one from.
    pub secret_hash: String,
    pub created_at: DateTime<Utc>,
    /// None: never expires (a ttl of 0).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// What the operator wrote of it, shown in the listing.
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The host id the token is bound to; empty: any valid id.
    #[serde(default)]
    pub host: String,
    /// The address (`10.42.0.12`) or network (`10.42.0.0/24`) the join must come from; empty:
    /// from anywhere.
    #[serde(default)]
    pub address: String,
    /// How many joins it took, and the last of them.
    #[serde(default)]
    pub uses: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<api::JoinTokenUse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// What a mint is asked for.
#[derive(Clone, Debug, Default)]
pub struct TokenSpec {
    /// None: the default; zero: never expires.
    pub ttl: Option<Duration>,
    pub description: String,
    pub region: String,
    pub labels: BTreeMap<String, String>,
    pub host: String,
    pub address: String,
}

/// Why a presented token is not taken. The caller is told one thing for all of them; the log
/// says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    Unknown,
    WrongSecret,
    /// Not from the address or network the token is bound to.
    WrongAddress,
    Expired,
    Revoked,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::Malformed => "not shaped <id>.<secret>",
            TokenError::Unknown => "no such token",
            TokenError::WrongSecret => "wrong secret",
            TokenError::WrongAddress => "not from the address the token is bound to",
            TokenError::Expired => "expired",
            TokenError::Revoked => "revoked",
        })
    }
}

/// Why a revoke is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeError {
    Unknown,
}

/// A token's use count and last use, as they were before a join: put back when the registry
/// could not be written and the host never got its answer.
#[derive(Clone, Debug)]
pub struct UseSnapshot {
    uses: u32,
    last_used: Option<api::JoinTokenUse>,
}

/// `len` characters of `[a-z0-9]`, drawn without bias (a byte over 251 is thrown away).
fn random_alnum(len: usize) -> String {
    use rand::RngCore;
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(len);
    let mut b = [0u8; 32];
    while out.len() < len {
        rand::rngs::OsRng.fill_bytes(&mut b);
        for x in b.iter().filter(|x| **x < 252) {
            if out.len() < len {
                out.push(ALPHABET[(*x % 36) as usize] as char);
            }
        }
    }
    out
}

fn hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// A token's address binding: an IPv4 address (a network of one) or an `a.b.c.d/n` network.
pub fn parse_address(s: &str) -> anyhow::Result<crate::bootstrap::Network> {
    let bad = || anyhow::anyhow!("{s:?}: want an IPv4 address or network, a.b.c.d or a.b.c.d/n");
    if s.contains('/') {
        return crate::bootstrap::Network::parse(s).map_err(|_| bad());
    }
    let addr: std::net::Ipv4Addr = s.parse().map_err(|_| bad())?;
    Ok(crate::bootstrap::Network { addr, prefix: 32 })
}

impl JoinTokenRec {
    /// `active`, `expired` or `revoked`.
    pub fn state(&self, now: DateTime<Utc>) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at.is_some_and(|at| now >= at) {
            "expired"
        } else {
            "active"
        }
    }

    pub fn to_api(&self, now: DateTime<Utc>) -> api::JoinToken {
        api::JoinToken {
            id: self.id.clone(),
            state: self.state(now).into(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            description: self.description.clone(),
            uses: self.uses,
            last_used: self.last_used.clone(),
            region: self.region.clone(),
            labels: self.labels.clone(),
            host: self.host.clone(),
            address: self.address.clone(),
            revoked_at: self.revoked_at,
        }
    }

    /// Whether a join from `ip` may use it: always when it is bound to no address.
    pub fn allows(&self, ip: std::net::Ipv4Addr) -> bool {
        self.address.is_empty() || parse_address(&self.address).is_ok_and(|net| net.contains(ip))
    }

    /// When it stopped being usable; None: it has not.
    fn ended(&self) -> Option<DateTime<Utc>> {
        [self.expires_at, self.revoked_at]
            .into_iter()
            .flatten()
            .min()
    }
}

impl Registry {
    /// Makes a token and returns it whole (`<id>.<secret>`), the one time it exists in clear.
    /// The caller writes the registry before the token is answered.
    pub fn mint_token(&mut self, spec: TokenSpec, now: DateTime<Utc>) -> (String, JoinTokenRec) {
        self.join_tokens
            .retain(|t| t.ended().is_none_or(|at| now - at < KEEP_ENDED));
        let id = loop {
            let id = random_alnum(6);
            if !self.join_tokens.iter().any(|t| t.id == id) {
                break id;
            }
        };
        let secret = random_alnum(16);
        let ttl = spec.ttl.unwrap_or(DEFAULT_TTL);
        let rec = JoinTokenRec {
            id: id.clone(),
            secret_hash: hash(&secret),
            created_at: now,
            expires_at: (!ttl.is_zero()).then(|| now + ttl),
            description: spec.description,
            region: spec.region,
            labels: spec.labels,
            host: spec.host,
            address: spec.address,
            uses: 0,
            last_used: None,
            revoked_at: None,
        };
        self.join_tokens.push(rec.clone());
        (format!("{id}.{secret}"), rec)
    }

    /// The token a presented `<id>.<secret>` is, when it can still be used.
    pub fn check_token(
        &self,
        presented: &str,
        now: DateTime<Utc>,
    ) -> Result<&JoinTokenRec, TokenError> {
        let (id, secret) = presented.split_once('.').ok_or(TokenError::Malformed)?;
        let rec = self
            .join_tokens
            .iter()
            .find(|t| t.id == id)
            .ok_or(TokenError::Unknown)?;
        if !api::constant_eq(hash(secret).as_bytes(), rec.secret_hash.as_bytes()) {
            return Err(TokenError::WrongSecret);
        }
        match rec.state(now) {
            "revoked" => Err(TokenError::Revoked),
            "expired" => Err(TokenError::Expired),
            _ => Ok(rec),
        }
    }

    /// Checks a token and counts a use by `by`, in one step under the registry's lock. A token
    /// is not spent: it takes joins until it expires or is revoked. Returns the token and what
    /// to put back should the registry not be written.
    pub fn consume_token(
        &mut self,
        presented: &str,
        now: DateTime<Utc>,
        by: api::JoinTokenUse,
    ) -> Result<(JoinTokenRec, UseSnapshot), TokenError> {
        let id = self.check_token(presented, now)?.id.clone();
        let rec = self
            .join_tokens
            .iter_mut()
            .find(|t| t.id == id)
            .expect("the token was just found");
        let before = UseSnapshot {
            uses: rec.uses,
            last_used: rec.last_used.take(),
        };
        rec.uses = rec.uses.saturating_add(1);
        rec.last_used = Some(by);
        Ok((rec.clone(), before))
    }

    /// Takes a use back: the registry could not be written, and the host never got its answer.
    pub fn release_token(&mut self, id: &str, before: UseSnapshot) {
        if let Some(t) = self.join_tokens.iter_mut().find(|t| t.id == id) {
            t.uses = before.uses;
            t.last_used = before.last_used;
        }
    }

    /// Ends a token, whatever it was used for; hosts that joined with it stay. A token already
    /// revoked keeps its first revoke. True when this call ended it (so a failed write can take it back, [`Registry::unrevoke_token`]).
    pub fn revoke_token(&mut self, id: &str, now: DateTime<Utc>) -> Result<bool, RevokeError> {
        let t = self
            .join_tokens
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(RevokeError::Unknown)?;
        let fresh = t.revoked_at.is_none();
        t.revoked_at.get_or_insert(now);
        Ok(fresh)
    }

    /// Takes a revoke back: the registry could not be written, and a restart would otherwise
    /// bring the token back active.
    pub fn unrevoke_token(&mut self, id: &str) {
        if let Some(t) = self.join_tokens.iter_mut().find(|t| t.id == id) {
            t.revoked_at = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn by(host: &str) -> api::JoinTokenUse {
        api::JoinTokenUse {
            host: host.into(),
            at: at(10),
            peer: "10.0.0.9".into(),
        }
    }

    /// A secret that is not the token's, of the same shape.
    fn flip(token: &str) -> String {
        let (id, secret) = token.split_once('.').unwrap();
        let first = if secret.starts_with('0') { "1" } else { "0" };
        format!("{id}.{first}{}", &secret[1..])
    }

    #[test]
    fn a_token_is_kubeadms_shape_and_only_the_hash_is_kept() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        let (id, secret) = token.split_once('.').unwrap();
        assert_eq!((id.len(), secret.len()), (6, 16), "{token}");
        assert!(token
            .bytes()
            .all(|c| c == b'.' || c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(rec.id, id);
        assert_eq!(rec.expires_at, Some(at(86_400)), "24 hours by default");
        let written = serde_json::to_string(&reg).unwrap();
        assert!(
            !written.contains(secret),
            "the secret is in no write: {written}"
        );
        assert!(written.contains(&rec.secret_hash));
        let (other, _) = reg.mint_token(TokenSpec::default(), at(0));
        assert_ne!(other, token);
    }

    #[test]
    fn a_token_takes_any_number_of_joins_and_keeps_count() {
        let mut reg = Registry::default();
        let (token, _) = reg.mint_token(TokenSpec::default(), at(0));
        reg.consume_token(&token, at(5), by("h1")).unwrap();
        let (rec, _) = reg.consume_token(&token, at(6), by("h2")).unwrap();
        assert_eq!(rec.uses, 2);
        assert_eq!(rec.last_used.unwrap().host, "h2");
        assert!(reg.check_token(&token, at(7)).is_ok(), "still good");
        let listed = reg.join_tokens[0].to_api(at(7));
        assert_eq!(listed.state, "active");
        assert_eq!(
            (listed.uses, listed.last_used.unwrap().host),
            (2, "h2".into())
        );
    }

    #[test]
    fn concurrent_joins_with_one_token_are_all_counted() {
        let reg = Arc::new(Mutex::new(Registry::default()));
        let (token, _) = reg.lock().unwrap().mint_token(TokenSpec::default(), at(0));
        let wins = (0..16)
            .map(|i| {
                let (reg, token) = (reg.clone(), token.clone());
                std::thread::spawn(move || {
                    let host = format!("h{i}");
                    reg.lock().unwrap().consume_token(&token, at(1), by(&host))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|t| t.join().unwrap().ok())
            .count();
        assert_eq!(wins, 16);
        assert_eq!(reg.lock().unwrap().join_tokens[0].uses, 16, "no use lost");
    }

    #[test]
    fn a_token_ends_at_its_expiry() {
        let mut reg = Registry::default();
        let spec = TokenSpec {
            ttl: Some(Duration::minutes(10)),
            ..Default::default()
        };
        let (token, rec) = reg.mint_token(spec, at(0));
        assert_eq!(rec.expires_at, Some(at(600)));
        assert!(reg.check_token(&token, at(599)).is_ok());
        assert_eq!(
            reg.check_token(&token, at(600)).unwrap_err(),
            TokenError::Expired
        );
        assert_eq!(rec.state(at(600)), "expired");
        assert_eq!(
            reg.consume_token(&token, at(601), by("h1")).unwrap_err(),
            TokenError::Expired
        );
        assert_eq!(reg.join_tokens[0].uses, 0, "an expired token takes no use");
    }

    #[test]
    fn a_ttl_of_zero_never_expires() {
        let mut reg = Registry::default();
        let spec = TokenSpec {
            ttl: Some(Duration::zero()),
            ..Default::default()
        };
        let (token, rec) = reg.mint_token(spec, at(0));
        assert_eq!(rec.expires_at, None);
        let ten_years = 10 * 365 * 86_400;
        assert!(reg.check_token(&token, at(ten_years)).is_ok());
        assert_eq!(rec.to_api(at(ten_years)).state, "active");
        assert!(rec.to_api(at(0)).expires_at.is_none());
        // Written and read back, it still never expires.
        let back: Registry = serde_json::from_slice(&serde_json::to_vec(&reg).unwrap()).unwrap();
        assert!(back.check_token(&token, at(ten_years)).is_ok());
    }

    #[test]
    fn a_revoked_token_is_not_taken_even_after_uses() {
        let mut reg = Registry::default();
        let (first, a) = reg.mint_token(TokenSpec::default(), at(0));
        let (second, b) = reg.mint_token(TokenSpec::default(), at(0));
        assert!(
            reg.revoke_token(&a.id, at(1)).unwrap(),
            "ended by this call"
        );
        assert_eq!(
            reg.check_token(&first, at(2)).unwrap_err(),
            TokenError::Revoked
        );
        assert_eq!(reg.join_tokens[0].to_api(at(2)).state, "revoked");
        reg.consume_token(&second, at(2), by("h1")).unwrap();
        assert_eq!(reg.revoke_token(&b.id, at(3)), Ok(true), "a used one too");
        assert_eq!(
            reg.consume_token(&second, at(4), by("h2")).unwrap_err(),
            TokenError::Revoked
        );
        assert_eq!(reg.join_tokens[1].uses, 1, "the uses stay as the record");
        assert_eq!(reg.revoke_token("ffffff", at(3)), Err(RevokeError::Unknown));
    }

    #[test]
    fn a_wrong_secret_or_shape_is_not_a_token_and_uses_nothing() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        let (id, secret) = token.split_once('.').unwrap();
        let wrong = flip(&token);
        for (presented, why) in [
            (wrong.as_str(), TokenError::WrongSecret),
            (id, TokenError::Malformed),
            ("", TokenError::Malformed),
            ("ffffff.abc", TokenError::Unknown),
            (secret, TokenError::Malformed),
        ] {
            assert_eq!(
                reg.consume_token(presented, at(1), by("h1")).unwrap_err(),
                why,
                "{presented:?}"
            );
        }
        assert_eq!(
            reg.check_token(&token, at(1)).unwrap().id,
            rec.id,
            "still good"
        );
        assert_eq!(reg.join_tokens[0].uses, 0);
    }

    #[test]
    fn a_revoke_taken_back_leaves_the_token_active_and_a_second_revoke_is_not_new() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        assert_eq!(reg.revoke_token(&rec.id, at(1)), Ok(true));
        assert_eq!(reg.revoke_token(&rec.id, at(2)), Ok(false));
        assert_eq!(
            reg.join_tokens[0].revoked_at,
            Some(at(1)),
            "the first time kept"
        );
        reg.unrevoke_token(&rec.id);
        assert!(reg.check_token(&token, at(3)).is_ok());
    }

    #[test]
    fn an_address_binding_is_an_ip_or_a_network() {
        for ok in ["10.42.0.12", "10.42.0.0/24", "0.0.0.0/0"] {
            assert!(parse_address(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "host",
            "10.42.0",
            "10.42.0.12/33",
            "::1",
            "10.0.0.0/x",
            "10.0.0.1/",
        ] {
            assert!(parse_address(bad).is_err(), "{bad:?}");
        }
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        let mut reg = Registry::default();
        let mut bound = |address: &str| {
            reg.mint_token(
                TokenSpec {
                    address: address.into(),
                    ..Default::default()
                },
                at(0),
            )
            .1
        };
        let one = bound("10.42.0.12");
        assert!(one.allows(ip("10.42.0.12")));
        assert!(!one.allows(ip("10.42.0.13")));
        let net = bound("10.42.0.0/24");
        assert!(net.allows(ip("10.42.0.255")) && !net.allows(ip("10.42.1.1")));
        assert!(
            bound("").allows(ip("203.0.113.9")),
            "unbound: from anywhere"
        );
        assert_eq!(net.to_api(at(1)).address, "10.42.0.0/24");
    }

    #[test]
    fn a_use_taken_back_leaves_the_count_and_last_use_as_they_were() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        reg.consume_token(&token, at(1), by("h1")).unwrap();
        let (_, before) = reg.consume_token(&token, at(2), by("h2")).unwrap();
        reg.release_token(&rec.id, before);
        let t = &reg.join_tokens[0];
        assert_eq!(
            (t.uses, t.last_used.as_ref().unwrap().host.as_str()),
            (1, "h1")
        );
    }

    #[test]
    fn tokens_that_ended_long_ago_are_dropped_at_the_next_mint() {
        let mut reg = Registry::default();
        let (used, _) = reg.mint_token(TokenSpec::default(), at(0));
        reg.consume_token(&used, at(1), by("h1")).unwrap();
        let (_, revoked) = reg.mint_token(TokenSpec::default(), at(0));
        reg.revoke_token(&revoked.id, at(2)).unwrap();
        let (_, expired) = reg.mint_token(
            TokenSpec {
                ttl: Some(Duration::hours(1)),
                ..Default::default()
            },
            at(0),
        );
        let (_, never) = reg.mint_token(
            TokenSpec {
                ttl: Some(Duration::zero()),
                ..Default::default()
            },
            at(0),
        );
        let (_, long) = reg.mint_token(
            TokenSpec {
                ttl: Some(Duration::days(365)),
                ..Default::default()
            },
            at(0),
        );
        let day = 86_400;
        reg.mint_token(TokenSpec::default(), at(20 * day));
        assert_eq!(reg.join_tokens.len(), 6, "kept for the audit");
        reg.mint_token(TokenSpec::default(), at(40 * day));
        let ids: Vec<_> = reg.join_tokens.iter().map(|t| t.id.clone()).collect();
        assert!(!ids.contains(&expired.id), "{ids:?}");
        assert!(!ids.contains(&revoked.id), "{ids:?}");
        assert!(
            ids.contains(&never.id),
            "a token that never expires stays: {ids:?}"
        );
        assert!(ids.contains(&long.id), "a token still valid stays: {ids:?}");
    }

    #[test]
    fn tokens_survive_the_registry_file() {
        let mut reg = Registry::default();
        let (token, _) = reg.mint_token(
            TokenSpec {
                region: "gra".into(),
                labels: [("rack".to_string(), "a1".to_string())].into(),
                host: "h1".into(),
                description: "the gra racks".into(),
                ..Default::default()
            },
            at(0),
        );
        reg.consume_token(&token, at(1), by("h1")).unwrap();
        let back: Registry = serde_json::from_slice(&serde_json::to_vec(&reg).unwrap()).unwrap();
        let rec = back.check_token(&token, at(1)).unwrap();
        assert_eq!((rec.region.as_str(), rec.host.as_str()), ("gra", "h1"));
        assert_eq!(rec.labels["rack"], "a1");
        assert_eq!(rec.description, "the gra racks");
        assert_eq!(rec.uses, 1);
    }
}
