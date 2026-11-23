use super::super::{
    cert::Usage, Actor, Endpoint, Inventory, LocalIdentity, Material, Name, Pair, PeerId, PeerRow,
};
use briqyard_api::execution::{
    clock::{ClockSource, QualifiedClock},
    sealed::prim::{HexDigest, Ident},
    Clock,
};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, TcpListener},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A settable qualified clock; `None` is the unqualified state.
pub(crate) struct TestClock(Mutex<Option<u64>>);

impl TestClock {
    pub(crate) fn at(year: i32, month: u8, day: u8) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(
            date_time_ymd(year, month, day).unix_timestamp() as u64,
        ))))
    }

    pub(crate) fn set(&self, now: Option<u64>) {
        *self.0.lock().unwrap() = now;
    }
}

impl ClockSource for TestClock {
    fn qualified(&self) -> Option<QualifiedClock> {
        let now = (*self.0.lock().unwrap())?;
        Some(QualifiedClock {
            interval: Clock {
                now,
                uncertainty: 1,
            },
            valid_until: Instant::now() + Duration::from_secs(1),
        })
    }
}

pub(crate) fn today() -> Arc<TestClock> {
    TestClock::at(2026, 11, 23)
}

/// A generated certificate and its PKCS#8 key.
#[derive(Clone)]
pub(crate) struct Issued {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl Issued {
    /// The pins of these exact bytes, taken without applying the profile.
    pub(crate) fn pair(&self) -> Pair {
        const PREFIX: [u8; 27] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        let at = self
            .cert
            .windows(PREFIX.len())
            .position(|w| w == PREFIX)
            .expect("P-256 SPKI in fixture");
        Pair {
            leaf: HexDigest::of(&self.cert),
            spki: HexDigest::of(&self.cert[at..at + 91]),
        }
    }

    pub(crate) fn material(&self) -> Material {
        Material::new(self.cert.clone(), Zeroizing::new(self.key.clone()))
    }
}

pub(crate) fn san(name: &Name) -> SanType {
    match name {
        Name::Dns(text) => SanType::DnsName(text.as_str().try_into().unwrap()),
        Name::Ip(ip) => SanType::IpAddress(*ip),
    }
}

/// A conforming leaf, then whatever `tweak` does to its parameters.
pub(crate) fn issue_with(
    name: &Name,
    usage: Usage,
    tweak: impl FnOnce(&mut CertificateParams),
) -> Issued {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![san(name)];
    params.extended_key_usages = vec![match usage {
        Usage::Server => ExtendedKeyUsagePurpose::ServerAuth,
        Usage::Client => ExtendedKeyUsagePurpose::ClientAuth,
    }];
    params.is_ca = IsCa::NoCa;
    params.not_before = date_time_ymd(2026, 1, 1);
    params.not_after = date_time_ymd(2030, 1, 1);
    tweak(&mut params);
    let cert = params.self_signed(&key).unwrap();
    Issued {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

pub(crate) fn issue(name: &Name, usage: Usage) -> Issued {
    issue_with(name, usage, |_| ())
}

pub(crate) fn ca_flags(params: &mut CertificateParams) {
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
}

pub(crate) struct Peer {
    pub id: PeerId,
    pub server: Issued,
    pub client: Issued,
}

/// A loopback deployment: one enrolled H, A, B, R and installer, each with its own two
/// identities and its own bound listener.
pub(crate) struct Net {
    pub peers: HashMap<Actor, Peer>,
    pub inventory: Arc<Inventory>,
    pub clock: Arc<TestClock>,
    listeners: Mutex<HashMap<Actor, TcpListener>>,
}

pub(crate) const ACTORS: [Actor; 5] = [Actor::A, Actor::B, Actor::H, Actor::R, Actor::Installer];

impl Net {
    pub(crate) fn new() -> Self {
        Self::build(|_, _| ())
    }

    /// `edit` may replace an actor's issued identities before the inventory pins them.
    pub(crate) fn build(edit: impl Fn(Actor, &mut Peer)) -> Self {
        let mut listeners = HashMap::new();
        let mut peers = HashMap::new();
        let mut rows = Vec::new();
        for actor in ACTORS {
            let listener = TcpListener::bind((LOOPBACK, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let id = PeerId {
                actor,
                id: Ident::new(format!("{}-1", actor.as_str())).unwrap(),
            };
            let mut peer = Peer {
                id: id.clone(),
                server: issue(&Name::Ip(LOOPBACK), Usage::Server),
                client: issue(
                    &Name::dns(&format!("{}-1.peer.test", actor.as_str().to_lowercase())).unwrap(),
                    Usage::Client,
                ),
            };
            edit(actor, &mut peer);
            rows.push(PeerRow {
                peer: id,
                endpoint: Endpoint::parse_any_port(&format!("https://127.0.0.1:{port}")).unwrap(),
                server_name: Name::Ip(LOOPBACK),
                server: peer.server.pair(),
                client: peer.client.pair(),
            });
            listeners.insert(actor, listener);
            peers.insert(actor, peer);
        }
        rows.sort_by_key(|row| (row.peer.actor.as_str(), row.peer.id.as_str().to_owned()));
        Self {
            peers,
            inventory: Arc::new(Inventory::new(rows, &[]).unwrap()),
            clock: today(),
            listeners: Mutex::new(listeners),
        }
    }

    pub(crate) fn local(&self, actor: Actor) -> LocalIdentity {
        let peer = &self.peers[&actor];
        LocalIdentity::new(
            &self.inventory,
            peer.id.clone(),
            peer.server.material(),
            peer.client.material(),
            self.clock.as_ref(),
        )
        .unwrap()
    }

    pub(crate) fn listener(&self, actor: Actor) -> TcpListener {
        self.listeners.lock().unwrap().remove(&actor).unwrap()
    }

    pub(crate) fn row(&self, actor: Actor) -> &PeerRow {
        self.inventory.only(actor).unwrap()
    }
}
