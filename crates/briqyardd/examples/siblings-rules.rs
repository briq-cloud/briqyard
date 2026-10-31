//! Rules for the disposable Linux packet fixture in hack/network-siblings.py.
use briqyardd::netw::nft::{attachment_elements, Policy, Ruleset};

fn main() {
    let via = |ip: &str, siblings| Policy::Via {
        ip: ip.into(),
        to: "10.64.1.2".into(),
        to_tap: "btgateway".into(),
        host: "10.64.1.1".into(),
        siblings,
    };
    let limited = Policy::Open {
        ip: "10.64.1.4".into(),
        limits: briqyardd::config::EgressLimits {
            blocked_ports: vec![25],
            new_connections_per_minute: 1000,
            bandwidth_mbit: 10,
        },
    };
    let opted = via("10.64.1.3", true);
    let strict = via("10.64.1.3", false);
    let rules = Ruleset {
        egress: "uplink".into(),
        range: "10.64.0.0/16".into(),
        allowed_clients: vec![],
        ports: vec!["7420".into()],
        host_ports: vec![8080],
        pins: vec![
            ("btgateway".into(), "10.64.1.2".into()),
            ("btclient".into(), "10.64.1.3".into()),
            ("btdatabase".into(), "10.64.1.4".into()),
            ("btstrict".into(), "10.64.1.5".into()),
            ("btother".into(), "10.64.2.2".into()),
        ],
        members: vec![
            ("by1".into(), "10.64.1.2".into()),
            ("by1".into(), "10.64.1.3".into()),
            ("by1".into(), "10.64.1.4".into()),
            ("by1".into(), "10.64.1.5".into()),
            ("by2".into(), "10.64.2.2".into()),
        ],
        policies: vec![opted.clone(), via("10.64.1.5", false)],
        counted: vec![],
    };
    let attachment = |verb, tap, ip, policy| attachment_elements(verb, tap, "by1", ip, policy);
    println!(
        "{}",
        serde_json::json!({
            "rules": rules.render(),
            "strict": attachment("delete", "btclient", "10.64.1.3", Some(&opted)) + &attachment("add", "btclient", "10.64.1.3", Some(&strict)),
            "opted": attachment("delete", "btclient", "10.64.1.3", Some(&strict)) + &attachment("add", "btclient", "10.64.1.3", Some(&opted)),
            "limited_add": attachment("add", "btdatabase", "10.64.1.4", Some(&limited)),
        "limited_remove": attachment("delete", "btdatabase", "10.64.1.4", Some(&limited)),
        "database_remove": attachment("delete", "btdatabase", "10.64.1.4", None),
            "database_add": attachment("add", "btdatabase", "10.64.1.4", None),
            "gateway_replace": attachment("delete", "btgateway", "10.64.1.2", None) + &attachment("add", "btreplaced", "10.64.1.2", None),
        })
    );
}
