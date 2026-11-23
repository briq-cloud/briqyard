use super::{pki::*, *};
use crate::execution_service::protected::transport::{
    cert::Usage, Actor, ConfigError, Endpoint, Inventory, LocalIdentity, Name, PeerId, PeerRow,
};
use briqyard_api::execution::sealed::prim::{HexDigest, Ident};

fn build(rows: Vec<PeerRow>, reserved: &[HexDigest]) -> Result<Inventory, ConfigError> {
    let roster: Vec<PeerId> = rows.iter().map(|row| row.peer.clone()).collect();
    Inventory::new(super::harness::x(), rows, &roster, reserved)
}

fn rows(net: &Net) -> Vec<PeerRow> {
    net.inventory.rows().cloned().collect()
}

fn reason(result: Result<Inventory, ConfigError>) -> &'static str {
    result.unwrap_err().0
}

#[test]
fn the_endpoint_is_an_exact_private_origin_on_the_dedicated_port_of_its_actor() {
    for (actor, text) in [
        (Actor::H, "https://10.0.0.1:7541"),
        (Actor::A, "https://10.0.0.1:7542"),
        (Actor::H, "https://[::1]:7541"),
        (Actor::A, "https://authority.private.test:7542"),
        (Actor::B, "https://api.private.test:9443"),
        (Actor::Installer, "https://10.0.0.7:9444"),
    ] {
        let endpoint = Endpoint::parse(actor, text).unwrap();
        assert_eq!(endpoint.origin(), text);
    }
    for (actor, text) in [
        (Actor::H, "https://10.0.0.1:7441"),
        (Actor::A, "https://10.0.0.1:7442"),
        (Actor::H, "https://10.0.0.1:7542"),
        (Actor::A, "https://10.0.0.1:7541"),
        (Actor::H, "https://10.0.0.1:443"),
        (Actor::B, "https://10.0.0.1:7541"),
        (Actor::B, "https://10.0.0.1:7542"),
        (Actor::B, "https://10.0.0.1:7441"),
        (Actor::B, "https://10.0.0.1:3003"),
        (Actor::B, "https://10.0.0.1:443"),
        (Actor::B, "https://10.0.0.1"),
        (Actor::B, "https://10.0.0.1:0"),
        (Actor::B, "https://10.0.0.1:09443"),
        (Actor::B, "https://10.0.0.1:65536"),
        (Actor::B, "http://10.0.0.1:9443"),
        (Actor::B, "https://user@10.0.0.1:9443"),
        (Actor::B, "https://10.0.0.1:9443/"),
        (Actor::B, "https://10.0.0.1:9443/path"),
        (Actor::B, "https://10.0.0.1:9443?q=1"),
        (Actor::B, "https://10.0.0.1:9443#f"),
        (Actor::B, "https://Api.private.test:9443"),
        (Actor::B, "https://*.private.test:9443"),
        (Actor::B, "https://api.private.test.:9443"),
        (Actor::B, "https://010.0.0.1:9443"),
        (Actor::B, "https://[0:0:0:0:0:0:0:1]:9443"),
        (Actor::B, "https://::1:9443"),
        (Actor::B, " https://10.0.0.1:9443"),
        (Actor::B, "https://10.0.0.1:9443 "),
    ] {
        assert!(Endpoint::parse(actor, text).is_err(), "{text}");
    }
}

#[test]
fn the_inventory_is_one_sorted_unique_set_of_distinct_identities() {
    let net = Net::new();
    assert!(build(rows(&net), &[]).is_ok());

    let mut reversed = rows(&net);
    reversed.reverse();
    assert_eq!(reason(build(reversed, &[])), "peer rows");
    let mut duplicate = rows(&net);
    duplicate.insert(1, duplicate[0].clone());
    assert_eq!(reason(build(duplicate, &[])), "peer rows");
    assert_eq!(reason(build(vec![], &[])), "peer rows");

    let mut without_host = rows(&net);
    without_host.retain(|row| row.peer.actor != Actor::H);
    assert_eq!(
        reason(build(without_host, &[])),
        "exactly one H, A, B and R"
    );
    let mut two_hosts = rows(&net);
    let mut second = two_hosts
        .iter()
        .find(|row| row.peer.actor == Actor::H)
        .unwrap()
        .clone();
    second.peer.id = Ident::new("h-2").unwrap();
    two_hosts.push(second);
    two_hosts.sort_by_key(|row| (row.peer.actor.as_str(), row.peer.id.as_str().to_owned()));
    assert_eq!(reason(build(two_hosts, &[])), "exactly one H, A, B and R");

    let mut shared = rows(&net);
    shared[1].server = shared[0].server.clone();
    assert_eq!(reason(build(shared, &[])), "identity is not distinct");
    let mut mixed = rows(&net);
    mixed[0].client = mixed[0].server.clone();
    assert_eq!(reason(build(mixed, &[])), "identity is not distinct");
    let mut same_origin = rows(&net);
    same_origin[1].endpoint = same_origin[0].endpoint.clone();
    assert_eq!(reason(build(same_origin, &[])), "endpoint is not unique");
}

#[test]
fn a_private_identity_may_not_equal_ordinary_or_signer_key_material() {
    let net = Net::new();
    let row = net.row(Actor::A);
    for reserved in [
        row.server.leaf.clone(),
        row.server.spki.clone(),
        row.client.leaf.clone(),
        row.client.spki.clone(),
    ] {
        assert_eq!(
            reason(build(rows(&net), &[reserved])),
            "identity is not distinct"
        );
    }
    assert!(build(rows(&net), &[HexDigest::of(b"unrelated")]).is_ok());
}

#[test]
fn a_local_identity_is_the_enrolled_pair_of_its_own_row_and_nothing_else() {
    let net = Net::new();
    let actor = Actor::A;
    let peer = net.peers[&actor].id.clone();
    let own = &net.peers[&actor];
    let build = |server: &Issued, client: &Issued, id: PeerId| {
        LocalIdentity::new(
            &net.inventory,
            id,
            server.material(),
            client.material(),
            net.clock.as_ref(),
        )
        .map(|_| ())
        .unwrap_err()
        .0
    };
    assert!(LocalIdentity::new(
        &net.inventory,
        peer.clone(),
        own.server.material(),
        own.client.material(),
        net.clock.as_ref()
    )
    .is_ok());

    let other = &net.peers[&Actor::H];
    assert_eq!(
        build(&other.server, &own.client, peer.clone()),
        "certificate does not match its enrolled pin"
    );
    assert_eq!(
        build(&own.server, &other.client, peer.clone()),
        "certificate does not match its enrolled pin"
    );
    assert_eq!(
        build(&own.client, &own.server, peer.clone()),
        "certificate does not match its enrolled pin"
    );
    assert_eq!(
        build(&own.server, &own.client, other.id.clone()),
        "certificate does not match its enrolled pin"
    );
    let stranger = PeerId {
        actor: Actor::A,
        id: Ident::new("a-9").unwrap(),
    };
    assert_eq!(build(&own.server, &own.client, stranger), "unenrolled peer");

    let key_swapped = Issued {
        cert: own.server.cert.clone(),
        key: other.server.key.clone(),
    };
    assert_eq!(
        build(&key_swapped, &own.client, peer.clone()),
        "private key does not match its certificate"
    );
    let not_a_key = Issued {
        cert: own.server.cert.clone(),
        key: vec![1, 2, 3],
    };
    assert_eq!(build(&not_a_key, &own.client, peer.clone()), "private key");

    net.clock.set(Some(1_000));
    assert_eq!(
        build(&own.server, &own.client, peer.clone()),
        "certificate validity"
    );
    net.clock.set(None);
    assert_eq!(
        build(&own.server, &own.client, peer),
        "certificate validity"
    );
}

#[test]
fn the_pinned_server_name_must_be_the_certificates_own_name() {
    let net = Net::build(|actor, peer| {
        if actor == Actor::A {
            peer.server = issue(&Name::dns("elsewhere.private.test").unwrap(), Usage::Server);
        }
    });
    let own = &net.peers[&Actor::A];
    let error = LocalIdentity::new(
        &net.inventory,
        own.id.clone(),
        own.server.material(),
        own.client.material(),
        net.clock.as_ref(),
    )
    .unwrap_err();
    assert_eq!(error.0, "server name");
}

#[test]
fn the_rows_are_exactly_the_verified_rosters_actors_for_this_operation() {
    let net = Net::new();
    let roster: Vec<PeerId> = rows(&net).iter().map(|row| row.peer.clone()).collect();
    let make = |roster: &[PeerId]| {
        Inventory::new(super::harness::x(), rows(&net), roster, &[]).map(|_| ())
    };
    assert!(make(&roster).is_ok());
    let wrong = "peer rows are not the roster";
    assert_eq!(make(&roster[1..]).unwrap_err().0, wrong);
    let mut extra = roster.clone();
    extra.push(PeerId {
        actor: Actor::Installer,
        id: Ident::new("i-2").unwrap(),
    });
    assert_eq!(make(&extra).unwrap_err().0, wrong);
    let mut renamed = roster.clone();
    renamed[2].id = Ident::new("h-9").unwrap();
    assert_eq!(make(&renamed).unwrap_err().0, wrong);
    let mut swapped = roster.clone();
    swapped.swap(0, 1);
    assert_eq!(make(&swapped).unwrap_err().0, wrong);
    assert_eq!(make(&[]).unwrap_err().0, wrong);
    assert_eq!(net.inventory.x(), &super::harness::x());
}
