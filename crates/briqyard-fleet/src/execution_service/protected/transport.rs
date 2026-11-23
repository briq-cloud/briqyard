//! Private transport for the protected authority (interface v3.1 "HTTP/IPC interface" and
//! v3.3 "Private identities"). Fixed-origin adapters over TLS 1.3 with mutual, exact-leaf
//! pinning: nothing here forwards a request, discovers a certificate or key, resolves a
//! trust anchor, follows a redirect, retries, or consults the environment.
//!
//! * [`cert`]: the only certificate profile a pinned identity may have.
//! * [`tls`]: strict in-memory rustls configurations built from the pinned inventory.
//! * [`http`]: one request per connection, bounded raw bytes in and out.
//! * [`routes`]: the closed route table, its ACL, the client adapters and the server mounts.
//!
//! Authority comes from the enrolled (actor, id) a pinned client leaf maps to, the route's
//! ACL, the signer key the signed query names for that actor, and the service's own
//! verification of the signed bytes. Possessing a certificate widens none of them.
//!
//! The module consumes already independently validated inputs (the `closure.peers` rows,
//! the local identity bytes from the sealed descriptors, a qualified clock). It owns no
//! provisioning, no file or environment reads and no readiness state.
#![allow(
    dead_code,
    unused_imports,
    reason = "consumed by the native startup integration, which supplies the sealed inputs"
)]

mod cert;
mod http;
mod routes;
mod tls;

#[cfg(test)]
pub(in crate::execution_service::protected) mod tests;

#[cfg(test)]
pub(crate) use routes::ApiService;
pub(crate) use routes::{
    AuthorityPeers, AuthorityService, Caller, HostLinks, HostPeers, HostService, Mount,
    PrivateServer, Route, Scope,
};

use briqyard_api::execution::{
    clock::ClockSource,
    sealed::{
        objects::X,
        prim::{HexDigest, Ident},
    },
};
use cert::Usage;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use rustls::pki_types::ServerName;
use std::{collections::HashSet, net::IpAddr};
use zeroize::Zeroizing;

const MAX_PEERS: usize = 64;
const HOST_PORT: u16 = 7541;
const AUTHORITY_PORT: u16 = 7542;
const FORBIDDEN_PORTS: [u16; 5] = [80, 443, 3003, 7441, 7442];

/// A configuration refusal. Static text only: no certificate, key or name is echoed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConfigError(pub(crate) &'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protected transport configuration refused: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The enrolled actors of the closure's `peers` array.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Actor {
    H,
    A,
    B,
    R,
    Installer,
    Gateway,
}

impl Actor {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::H => "H",
            Self::A => "A",
            Self::B => "B",
            Self::R => "R",
            Self::Installer => "installer",
            Self::Gateway => "gateway",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        [
            Self::H,
            Self::A,
            Self::B,
            Self::R,
            Self::Installer,
            Self::Gateway,
        ]
        .into_iter()
        .find(|actor| actor.as_str() == text)
    }
}

/// One enrolled service instance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PeerId {
    pub actor: Actor,
    pub id: Ident,
}

pub(crate) use briqyard_api::execution::private_cert::{Name, Pair};

/// Parsing and rustls conversion stay with the transport; the name type itself is shared.
pub(crate) trait NameExt: Sized {
    fn parse(text: &str) -> Result<Self, ConfigError>;
    fn server_name(&self) -> ServerName<'static>;
}

impl NameExt for Name {
    fn parse(text: &str) -> Result<Self, ConfigError> {
        match text.parse::<IpAddr>() {
            Ok(ip) if ip.to_string() == text => Ok(Self::Ip(ip)),
            Ok(_) => Err(ConfigError("non-canonical address literal")),
            Err(_) => Self::dns(text).ok_or(ConfigError("name")),
        }
    }

    fn server_name(&self) -> ServerName<'static> {
        match self {
            Self::Dns(text) => ServerName::try_from(text.clone()).expect("validated DNS name"),
            Self::Ip(ip) => ServerName::IpAddress((*ip).into()),
        }
    }
}

/// An exact private HTTPS origin: scheme, host and explicit port, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    host: Name,
    port: u16,
}

impl Endpoint {
    /// H listens on 7541 and A on 7542; no endpoint may use an ordinary or public port, and
    /// no other actor may sit on the dedicated ones.
    pub(crate) fn parse(actor: Actor, text: &str) -> Result<Self, ConfigError> {
        let endpoint = Self::parse_origin(text)?;
        let wanted = match actor {
            Actor::H => Some(HOST_PORT),
            Actor::A => Some(AUTHORITY_PORT),
            _ => None,
        };
        let allowed = match wanted {
            Some(port) => endpoint.port == port,
            None => ![HOST_PORT, AUTHORITY_PORT].contains(&endpoint.port),
        };
        if !allowed || FORBIDDEN_PORTS.contains(&endpoint.port) {
            return Err(ConfigError("endpoint port"));
        }
        Ok(endpoint)
    }

    fn parse_origin(text: &str) -> Result<Self, ConfigError> {
        let rest = text
            .strip_prefix("https://")
            .ok_or(ConfigError("endpoint scheme"))?;
        let (host, port) = match rest.strip_prefix('[') {
            Some(bracketed) => bracketed
                .split_once("]:")
                .ok_or(ConfigError("endpoint authority"))?,
            None => rest
                .split_once(':')
                .ok_or(ConfigError("endpoint authority"))?,
        };
        let digits = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
        let port: u16 = port
            .parse::<u16>()
            .ok()
            .filter(|p| digits && *p != 0 && p.to_string() == port)
            .ok_or(ConfigError("endpoint port"))?;
        let host = Name::parse(host)?;
        if text.starts_with("https://[") != matches!(host, Name::Ip(IpAddr::V6(_))) {
            return Err(ConfigError("endpoint authority"));
        }
        let endpoint = Self { host, port };
        if endpoint.origin() != text {
            return Err(ConfigError("endpoint is not an exact origin"));
        }
        Ok(endpoint)
    }

    #[cfg(test)]
    pub(crate) fn parse_any_port(text: &str) -> Result<Self, ConfigError> {
        Self::parse_origin(text)
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// The `Host` header value.
    pub(crate) fn authority(&self) -> String {
        match &self.host {
            Name::Dns(text) => format!("{text}:{}", self.port),
            Name::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            Name::Ip(ip) => format!("{ip}:{}", self.port),
        }
    }

    pub(crate) fn origin(&self) -> String {
        format!("https://{}", self.authority())
    }
}

/// One row of the closure's `peers` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerRow {
    peer: PeerId,
    endpoint: Endpoint,
    server_name: Name,
    server: Pair,
    client: Pair,
}

impl PeerRow {
    pub(crate) fn new(
        actor: Actor,
        id: &str,
        endpoint: &str,
        server_name: &str,
        server: Pair,
        client: Pair,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            peer: PeerId {
                actor,
                id: Ident::new(id).map_err(|_| ConfigError("peer id"))?,
            },
            endpoint: Endpoint::parse(actor, endpoint)?,
            server_name: Name::parse(server_name)?,
            server,
            client,
        })
    }
}

/// The enrolled peers, validated as a set: sorted and unique by (actor, id), exactly one
/// H, A, B and R (one host, one registered predecessor), and every pinned server and client
/// identity distinct from every other and from the reserved key material.
#[derive(Debug)]
pub(crate) struct Inventory {
    x: X,
    rows: Vec<PeerRow>,
}

impl Inventory {
    /// `x` is the operation of the independently verified inputs, `roster` their `actors`
    /// key set in (actor, id) order, which the `closure.peers` rows must equal one to one.
    /// `reserved` holds digests of the ordinary TLS leaf and SPKI, the Hk/Ak/Bk/Rk and
    /// ordinary authority keys and every other identity a private one must not equal.
    pub(crate) fn new(
        x: X,
        rows: Vec<PeerRow>,
        roster: &[PeerId],
        reserved: &[HexDigest],
    ) -> Result<Self, ConfigError> {
        let key = |row: &PeerRow| (row.peer.actor.as_str(), row.peer.id.as_str().to_owned());
        if rows.is_empty()
            || rows.len() > MAX_PEERS
            || rows.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1]))
        {
            return Err(ConfigError("peer rows"));
        }
        if !rows.iter().map(|row| &row.peer).eq(roster.iter()) {
            return Err(ConfigError("peer rows are not the roster"));
        }
        for actor in [Actor::H, Actor::A, Actor::B, Actor::R] {
            if rows.iter().filter(|row| row.peer.actor == actor).count() != 1 {
                return Err(ConfigError("exactly one H, A, B and R"));
            }
        }
        let mut digests = HashSet::new();
        let mut origins = HashSet::new();
        for row in &rows {
            for pair in [&row.server, &row.client] {
                for digest in [&pair.leaf, &pair.spki] {
                    if reserved.contains(digest) || !digests.insert(digest.clone()) {
                        return Err(ConfigError("identity is not distinct"));
                    }
                }
            }
            if !origins.insert(row.endpoint.origin()) {
                return Err(ConfigError("endpoint is not unique"));
            }
        }
        Ok(Self { x, rows })
    }

    pub(crate) fn x(&self) -> &X {
        &self.x
    }

    pub(crate) fn rows(&self) -> impl Iterator<Item = &PeerRow> {
        self.rows.iter()
    }

    pub(crate) fn row(&self, peer: &PeerId) -> Option<&PeerRow> {
        self.rows.iter().find(|row| row.peer == *peer)
    }

    /// The one enrolled H, A, B or R.
    pub(crate) fn only(&self, actor: Actor) -> Result<&PeerRow, ConfigError> {
        self.rows
            .iter()
            .find(|row| row.peer.actor == actor)
            .ok_or(ConfigError("peer actor"))
    }

    pub(crate) fn by_client_leaf(&self, leaf: &HexDigest) -> Option<&PeerRow> {
        self.rows.iter().find(|row| row.client.leaf == *leaf)
    }
}

/// A certificate and its PKCS#8 key, from the sealed descriptors. The key buffer is
/// cleared when this is dropped.
pub(crate) struct Material {
    cert: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
}

impl Material {
    pub(crate) fn new(cert: Vec<u8>, key: Zeroizing<Vec<u8>>) -> Self {
        Self { cert, key }
    }
}

/// This service's own two identities, checked against its enrolled row: digests, profile,
/// qualified validity, one key per certificate, and a server key distinct from the client key.
pub(crate) struct LocalIdentity {
    peer: PeerId,
    server: Material,
    client: Material,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl LocalIdentity {
    pub(crate) fn new(
        inventory: &Inventory,
        peer: PeerId,
        server: Material,
        client: Material,
        clock: &dyn ClockSource,
    ) -> Result<Self, ConfigError> {
        let row = inventory.row(&peer).ok_or(ConfigError("unenrolled peer"))?;
        let own = |material: &Material, pin: &Pair, usage| {
            let leaf = cert::verify(&material.cert, pin, usage)
                .map_err(|_| ConfigError("certificate does not match its enrolled pin"))?;
            leaf.valid_at(clock)
                .map_err(|_| ConfigError("certificate validity"))?;
            let pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &material.key,
                &SystemRandom::new(),
            )
            .map_err(|_| ConfigError("private key"))?;
            if pair.public_key().as_ref() != leaf.point() {
                return Err(ConfigError("private key does not match its certificate"));
            }
            Ok(leaf)
        };
        let server_leaf = own(&server, &row.server, Usage::Server)?;
        own(&client, &row.client, Usage::Client)?;
        if server_leaf.name != row.server_name {
            return Err(ConfigError("server name"));
        }
        if *server.key == *client.key {
            return Err(ConfigError("server and client share a key"));
        }
        Ok(Self {
            peer,
            server,
            client,
        })
    }

    pub(crate) fn peer(&self) -> &PeerId {
        &self.peer
    }
}
