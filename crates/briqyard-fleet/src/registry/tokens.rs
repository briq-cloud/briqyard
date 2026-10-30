//! Join tokens (ADR 0057): one-time, expiring, `<id>.<secret>`; the registry keeps the id and a
//! hash of the secret, never the secret.

use super::*;
use sha2::{Digest, Sha256};

/// How long a token lasts when none is asked, and the most it can be asked for.
pub const DEFAULT_TTL: Duration = Duration::hours(1);
pub const MAX_TTL: Duration = Duration::days(30);
/// A token that ended (used, revoked or expired) is kept this long for the audit, then dropped
/// by the next mint.
const KEEP_ENDED: Duration = Duration::days(30);

/// A join token as the registry keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinTokenRec {
    pub id: String,
    /// SHA-256 of the secret, hex. The secret has 128 random bits, so a fast hash is enough:
    /// there is nothing to guess one from.
    pub secret_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The host id the token is bound to; empty: any valid id.
    #[serde(default)]
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_by: Option<api::JoinTokenUse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// What a mint is asked for.
#[derive(Clone, Debug, Default)]
pub struct TokenSpec {
    pub ttl: Option<Duration>,
    pub region: String,
    pub labels: BTreeMap<String, String>,
    pub host: String,
}

/// Why a presented token is not taken. The caller is told one thing for all of them; the log
/// says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    Unknown,
    WrongSecret,
    Expired,
    Used,
    Revoked,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::Malformed => "not shaped <id>.<secret>",
            TokenError::Unknown => "no such token",
            TokenError::WrongSecret => "wrong secret",
            TokenError::Expired => "expired",
            TokenError::Used => "already used",
            TokenError::Revoked => "revoked",
        })
    }
}

/// Why a revoke is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeError {
    Unknown,
    Used,
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

impl JoinTokenRec {
    /// `active`, `used`, `expired` or `revoked`.
    pub fn state(&self, now: DateTime<Utc>) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.used_by.is_some() {
            "used"
        } else if now >= self.expires_at {
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
            region: self.region.clone(),
            labels: self.labels.clone(),
            host: self.host.clone(),
            used_by: self.used_by.clone(),
            revoked_at: self.revoked_at,
        }
    }

    /// When it stopped being usable.
    fn ended(&self) -> DateTime<Utc> {
        [self.used_by.as_ref().map(|u| u.at), self.revoked_at]
            .into_iter()
            .flatten()
            .min()
            .map_or(self.expires_at, |at| at.min(self.expires_at))
    }
}

impl Registry {
    /// Makes a token and returns it whole (`<id>.<secret>`), the one time it exists in clear.
    /// The caller writes the registry before the token is answered.
    pub fn mint_token(&mut self, spec: TokenSpec, now: DateTime<Utc>) -> (String, JoinTokenRec) {
        self.join_tokens.retain(|t| now - t.ended() < KEEP_ENDED);
        let id = loop {
            let id = random_hex(3);
            if !self.join_tokens.iter().any(|t| t.id == id) {
                break id;
            }
        };
        let secret = random_hex(16);
        let rec = JoinTokenRec {
            id: id.clone(),
            secret_hash: hash(&secret),
            created_at: now,
            expires_at: now + spec.ttl.unwrap_or(DEFAULT_TTL),
            region: spec.region,
            labels: spec.labels,
            host: spec.host,
            used_by: None,
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
            "used" => Err(TokenError::Used),
            "expired" => Err(TokenError::Expired),
            _ => Ok(rec),
        }
    }

    /// Checks a token and marks it used by `by`, in one step: of any number of callers with the
    /// same token, one gets it.
    pub fn consume_token(
        &mut self,
        presented: &str,
        now: DateTime<Utc>,
        by: api::JoinTokenUse,
    ) -> Result<JoinTokenRec, TokenError> {
        let id = self.check_token(presented, now)?.id.clone();
        let rec = self
            .join_tokens
            .iter_mut()
            .find(|t| t.id == id)
            .expect("the token was just found");
        rec.used_by = Some(by);
        Ok(rec.clone())
    }

    /// Takes a use back: the registry could not be written, and the host never got its answer.
    pub fn release_token(&mut self, id: &str) {
        if let Some(t) = self.join_tokens.iter_mut().find(|t| t.id == id) {
            t.used_by = None;
        }
    }

    /// Ends a token that no host has used. A revoked or expired one stays revoked.
    pub fn revoke_token(&mut self, id: &str, now: DateTime<Utc>) -> Result<(), RevokeError> {
        let t = self
            .join_tokens
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(RevokeError::Unknown)?;
        if t.used_by.is_some() {
            return Err(RevokeError::Used);
        }
        t.revoked_at.get_or_insert(now);
        Ok(())
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

    #[test]
    fn a_token_is_an_id_and_a_secret_and_only_the_hash_is_kept() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        let (id, secret) = token.split_once('.').unwrap();
        assert_eq!((id.len(), secret.len()), (6, 32), "{token}");
        assert!(token.bytes().all(|c| c == b'.' || c.is_ascii_hexdigit()));
        assert_eq!(rec.id, id);
        assert_eq!(rec.expires_at, at(3600), "an hour by default");
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
    fn a_token_is_used_once() {
        let mut reg = Registry::default();
        let (token, _) = reg.mint_token(TokenSpec::default(), at(0));
        let rec = reg.consume_token(&token, at(5), by("h1")).unwrap();
        assert_eq!(rec.used_by.unwrap().host, "h1");
        assert_eq!(
            reg.consume_token(&token, at(6), by("h2")).unwrap_err(),
            TokenError::Used
        );
        let listed = reg.join_tokens[0].to_api(at(7));
        assert_eq!(listed.state, "used");
        assert_eq!(listed.used_by.unwrap().host, "h1", "who used it is kept");
    }

    #[test]
    fn only_one_of_many_concurrent_consumes_wins() {
        let reg = Arc::new(Mutex::new(Registry::default()));
        let (token, _) = reg.lock().unwrap().mint_token(TokenSpec::default(), at(0));
        let wins: Vec<_> = (0..16)
            .map(|i| {
                let (reg, token) = (reg.clone(), token.clone());
                std::thread::spawn(move || {
                    let host = format!("h{i}");
                    let got = reg.lock().unwrap().consume_token(&token, at(1), by(&host));
                    got.map(|_| host)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|t| t.join().unwrap().ok())
            .collect();
        assert_eq!(wins.len(), 1, "one winner: {wins:?}");
        let reg = reg.lock().unwrap();
        assert_eq!(reg.join_tokens[0].used_by.as_ref().unwrap().host, wins[0]);
    }

    #[test]
    fn a_token_ends_at_its_expiry() {
        let mut reg = Registry::default();
        let spec = TokenSpec {
            ttl: Some(Duration::minutes(10)),
            ..Default::default()
        };
        let (token, rec) = reg.mint_token(spec, at(0));
        assert_eq!(rec.expires_at, at(600));
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
        assert!(
            reg.join_tokens[0].used_by.is_none(),
            "an expired token is not used"
        );
    }

    #[test]
    fn a_revoked_token_is_not_taken_and_a_used_one_cannot_be_revoked() {
        let mut reg = Registry::default();
        let (first, a) = reg.mint_token(TokenSpec::default(), at(0));
        let (second, b) = reg.mint_token(TokenSpec::default(), at(0));
        reg.revoke_token(&a.id, at(1)).unwrap();
        assert_eq!(
            reg.check_token(&first, at(2)).unwrap_err(),
            TokenError::Revoked
        );
        assert_eq!(reg.join_tokens[0].to_api(at(2)).state, "revoked");
        reg.consume_token(&second, at(2), by("h1")).unwrap();
        assert_eq!(reg.revoke_token(&b.id, at(3)), Err(RevokeError::Used));
        assert_eq!(reg.revoke_token("ffffff", at(3)), Err(RevokeError::Unknown));
    }

    #[test]
    fn a_wrong_secret_or_shape_is_not_a_token_and_uses_nothing() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        let (id, secret) = token.split_once('.').unwrap();
        let wrong = format!("{id}.{}", secret.replace(&secret[..1], "z"));
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
    }

    #[test]
    fn a_use_taken_back_leaves_the_token_whole() {
        let mut reg = Registry::default();
        let (token, rec) = reg.mint_token(TokenSpec::default(), at(0));
        reg.consume_token(&token, at(1), by("h1")).unwrap();
        reg.release_token(&rec.id);
        assert!(reg.consume_token(&token, at(2), by("h2")).is_ok());
    }

    #[test]
    fn tokens_that_ended_long_ago_are_dropped_at_the_next_mint() {
        let mut reg = Registry::default();
        let (used, _) = reg.mint_token(TokenSpec::default(), at(0));
        reg.consume_token(&used, at(1), by("h1")).unwrap();
        let (_, expired) = reg.mint_token(TokenSpec::default(), at(0));
        let (_, active) = reg.mint_token(
            TokenSpec {
                ttl: Some(MAX_TTL),
                ..Default::default()
            },
            at(0),
        );
        let day = 86_400;
        reg.mint_token(TokenSpec::default(), at(20 * day));
        assert_eq!(reg.join_tokens.len(), 4, "kept for the audit");
        reg.mint_token(TokenSpec::default(), at(40 * day));
        let ids: Vec<_> = reg.join_tokens.iter().map(|t| t.id.clone()).collect();
        assert!(!ids.contains(&expired.id), "{ids:?}");
        assert!(ids.contains(&active.id), "an active token stays: {ids:?}");
        assert!(
            reg.join_tokens.iter().all(|t| t.used_by.is_none()),
            "{ids:?}"
        );
    }

    #[test]
    fn tokens_survive_the_registry_file() {
        let mut reg = Registry::default();
        let (token, _) = reg.mint_token(
            TokenSpec {
                region: "gra".into(),
                labels: [("rack".to_string(), "a1".to_string())].into(),
                host: "h1".into(),
                ..Default::default()
            },
            at(0),
        );
        let back: Registry = serde_json::from_slice(&serde_json::to_vec(&reg).unwrap()).unwrap();
        let rec = back.check_token(&token, at(1)).unwrap();
        assert_eq!((rec.region.as_str(), rec.host.as_str()), ("gra", "h1"));
        assert_eq!(rec.labels["rack"], "a1");
    }
}
