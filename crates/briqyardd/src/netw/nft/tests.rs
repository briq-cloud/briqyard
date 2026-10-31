use super::*;

fn ruleset() -> Ruleset {
    Ruleset {
        egress: "eth0".into(),
        range: "10.64.0.0/10".into(),
        allowed_clients: vec!["10.0.0.0/8".into(), "192.168.64.1/32".into()],
        ports: daemon_ports("0.0.0.0:7420", "0.0.0.0:8080", "20000-29999").unwrap(),
        host_ports: vec![80, 443],
        pins: vec![
            ("btabcdef123456".into(), "10.64.0.2".into()),
            ("bt0000000000a3".into(), "10.64.0.3".into()),
            ("bt0000000000a4".into(), "10.64.0.4".into()),
        ],
        members: vec![
            ("by0".into(), "10.64.0.2".into()),
            ("by0".into(), "10.64.0.3".into()),
            ("by0".into(), "10.64.0.4".into()),
        ],
        policies: vec![
            open(),
            via(),
            Policy::None {
                ip: "10.64.0.4".into(),
            },
        ],
        counted: vec!["10.64.0.2".into(), "10.64.0.3".into()],
    }
}

/// 10.64.0.2 with every limit: two ports, 600 connections a minute, 100 Mbit/s.
fn open() -> Policy {
    Policy::Open {
        ip: "10.64.0.2".into(),
        limits: EgressLimits {
            blocked_ports: vec![25, 465],
            new_connections_per_minute: 600,
            bandwidth_mbit: 100,
        },
    }
}

/// 10.64.0.3 through its gateway machine 10.64.0.2.
fn via() -> Policy {
    Policy::Via {
        ip: "10.64.0.3".into(),
        to: "10.64.0.2".into(),
        to_tap: "btabcdef123456".into(),
        host: "10.64.0.1".into(),
        siblings: false,
    }
}

#[test]
fn the_inet_policy_is_unchanged() {
    let expected = r#"table inet briqyard
delete table inet briqyard
table inet briqyard {
	set allowed_clients {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 192.168.64.1/32 }
	}
	set egress_none {
		type ipv4_addr
		elements = { 10.64.0.4 }
	}
	set blocked_ports {
		type ipv4_addr . inet_service
		elements = { 10.64.0.2 . 25, 10.64.0.2 . 465 }
	}
	limit conn_10_64_0_2 {
		rate over 600/minute burst 600 packets
	}
	limit bandwidth_10_64_0_2 {
		rate over 12500000 bytes/second
	}
	map conn_limits {
		type ipv4_addr : limit
		elements = { 10.64.0.2 : "conn_10_64_0_2" }
	}
	map bandwidth_limits {
		type ipv4_addr : limit
		elements = { 10.64.0.2 : "bandwidth_10_64_0_2" }
	}
	set internet_out {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set internet_in {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set dropped_port {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set dropped_rate {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	set dropped_bandwidth {
		type ipv4_addr
		counter
		elements = { 10.64.0.2, 10.64.0.3 }
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		meta nfproto ipv6 iifname "by*" drop
		ip saddr @egress_none drop
		iifname "by*" oifname "eth0" ip saddr . tcp dport @blocked_ports ip saddr @dropped_port reject with tcp reset
		iifname "by*" oifname "eth0" ip saddr . udp dport @blocked_ports ip saddr @dropped_port reject
		iifname "by*" oifname "eth0" ct state new limit name ip saddr map @conn_limits ip saddr @dropped_rate drop
		iifname "by*" oifname "eth0" limit name ip saddr map @bandwidth_limits ip saddr @dropped_bandwidth drop
		iifname "eth0" oifname "by*" limit name ip daddr map @bandwidth_limits ip daddr @dropped_bandwidth drop
		iifname "by*" oifname "eth0" ip saddr @internet_out
		iifname "eth0" oifname "by*" ip daddr @internet_in
		ct state established,related accept
		iifname "by*" oifname "eth0" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
		iifname "by*" oifname "eth0" accept
	}
	chain input {
		type filter hook input priority 0; policy accept;
		iifname "lo" accept
		iifname "by*" ip saddr @egress_none tcp dport { 80, 443 } drop
		ct state established,related accept
		iifname "by*" udp dport 53 accept
		iifname "by*" tcp dport 53 accept
		iifname "by*" icmp type echo-request accept
		iifname "by*" ip daddr != 10.64.0.0/10 tcp dport { 80, 443 } accept
		iifname "by*" drop
		tcp dport { 7420, 8080, 20000-29999 } ip saddr @allowed_clients accept
		tcp dport { 7420, 8080, 20000-29999 } drop
	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr 10.64.0.0/10 oifname "eth0" masquerade
	}
}
"#;
    assert_eq!(
        ruleset().render().split("table bridge briqyard").next(),
        Some(expected)
    );
}

#[test]
fn no_clients_means_no_port_rules_and_empty_sets_have_no_elements() {
    let r = Ruleset {
        allowed_clients: vec![],
        host_ports: vec![],
        pins: vec![],
        members: vec![],
        policies: vec![],
        counted: vec![],
        ..ruleset()
    };
    let s = r.render();
    assert!(!s.contains("@allowed_clients"), "{s}");
    assert!(!s.contains("20000-29999"), "{s}");
    // No host ports: machines reach nothing on the host but its DNS and ping.
    assert!(!s.contains("tcp dport { 80"), "{s}");
    assert!(!s.contains("elements"), "{s}");
    assert!(s.contains("\tset allowed_clients {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n"));
    assert!(s.contains("\tset pins {\n\t\ttype ifname . ipv4_addr\n\t}\n"));
    assert!(s.contains("\tset egress_none {\n\t\ttype ipv4_addr\n\t}\n"));
    assert!(s.contains("\tset via_allowed {\n\t\ttype ipv4_addr . ipv4_addr\n\t}\n"));
    assert!(s.contains("\tset internet_in {\n\t\ttype ipv4_addr\n\t\tcounter\n\t}\n"));
    assert!(s.contains("\tset blocked_ports {\n\t\ttype ipv4_addr . inet_service\n\t}\n"));
    assert!(s.contains("\tmap conn_limits {\n\t\ttype ipv4_addr : limit\n\t}\n"));
    assert!(!s.contains("\tlimit "), "{s}");
}

#[test]
fn the_forward_chain_drops_by_default() {
    let s = ruleset().render();
    assert!(s.contains("hook forward priority 0; policy drop;"));
    // The only accepts: replies, and a namespace's way out through the egress interface.
    let accepts: Vec<&str> = s
        .lines()
        .skip_while(|l| !l.contains("chain forward"))
        .take_while(|l| !l.contains("chain input"))
        .filter(|l| l.ends_with("accept"))
        .map(str::trim)
        .collect();
    assert_eq!(
        accepts,
        [
            "ct state established,related accept",
            "iifname \"by*\" oifname \"eth0\" accept"
        ]
    );
}

#[test]
fn policy_elements() {
    assert_eq!(
        via().elements("add"),
        "add element bridge briqyard via_sources { 10.64.0.3 }\n\
         add element bridge briqyard via_allowed { 10.64.0.3 . 10.64.0.2, 10.64.0.3 . 10.64.0.1 }\n\
         add element bridge briqyard via_targets { 10.64.0.3 . \"btabcdef123456\" }\n"
    );
    let none = Policy::None {
        ip: "10.64.0.4".into(),
    };
    assert_eq!(
        none.elements("delete"),
        "delete element inet briqyard egress_none { 10.64.0.4 }\n"
    );
    assert_eq!((via().ip(), none.ip()), ("10.64.0.3", "10.64.0.4"));
    // A swap is one input, so one transaction: the old out, then the new in.
    let none3 = Policy::None {
        ip: "10.64.0.3".into(),
    };
    assert_eq!(
        swap_elements(&via(), &none3),
        "delete element bridge briqyard via_sources { 10.64.0.3 }\n\
         delete element bridge briqyard via_allowed { 10.64.0.3 . 10.64.0.2, 10.64.0.3 . 10.64.0.1 }\n\
         delete element bridge briqyard via_targets { 10.64.0.3 . \"btabcdef123456\" }\n\
         add element inet briqyard egress_none { 10.64.0.3 }\n"
    );
}

#[test]
fn limit_elements() {
    // Every limit: the ports, then each rate's named limit before the map element that
    // names it; taken out in the other order, the element before its limit.
    assert_eq!(
        open().elements("add"),
        "add element inet briqyard blocked_ports { 10.64.0.2 . 25, 10.64.0.2 . 465 }\n\
         add limit inet briqyard conn_10_64_0_2 { rate over 600/minute burst 600 packets }\n\
         add element inet briqyard conn_limits { 10.64.0.2 : \"conn_10_64_0_2\" }\n\
         add limit inet briqyard bandwidth_10_64_0_2 { rate over 12500000 bytes/second }\n\
         add element inet briqyard bandwidth_limits { 10.64.0.2 : \"bandwidth_10_64_0_2\" }\n"
    );
    assert_eq!(
        open().elements("delete"),
        "delete element inet briqyard blocked_ports { 10.64.0.2 . 25, 10.64.0.2 . 465 }\n\
         delete element inet briqyard conn_limits { 10.64.0.2 }\n\
         delete limit inet briqyard conn_10_64_0_2\n\
         delete element inet briqyard bandwidth_limits { 10.64.0.2 }\n\
         delete limit inet briqyard bandwidth_10_64_0_2\n"
    );
    // One limit alone: only its lines.
    let only = |limits| Policy::Open {
        ip: "10.64.1.9".into(),
        limits,
    };
    let rate = only(EgressLimits {
        blocked_ports: vec![],
        new_connections_per_minute: 6,
        bandwidth_mbit: 0,
    });
    assert_eq!(
        rate.elements("add"),
        "add limit inet briqyard conn_10_64_1_9 { rate over 6/minute burst 6 packets }\n\
         add element inet briqyard conn_limits { 10.64.1.9 : \"conn_10_64_1_9\" }\n"
    );
    let port = only(EgressLimits {
        blocked_ports: vec![25],
        new_connections_per_minute: 0,
        bandwidth_mbit: 0,
    });
    assert_eq!(
        port.elements("delete"),
        "delete element inet briqyard blocked_ports { 10.64.1.9 . 25 }\n"
    );
    // A change of rate is the same limit's name deleted and added again, in one input.
    let faster = Policy::Open {
        ip: "10.64.0.2".into(),
        limits: EgressLimits {
            bandwidth_mbit: 2,
            ..EgressLimits::default()
        },
    };
    assert_eq!(
        swap_elements(&open(), &faster),
        open().elements("delete") + &faster.elements("add")
    );
    assert!(faster.elements("add").contains(
        "add limit inet briqyard bandwidth_10_64_0_2 { rate over 250000 bytes/second }\n"
    ));
    // The resolver keeps `via` and `none` to internal names, never an open machine.
    assert!(!open().internal_only());
    assert!(via().internal_only());
    assert_eq!(open().ip(), "10.64.0.2");
}

#[test]
fn counter_elements_name_every_set() {
    assert_eq!(
        counter_elements("add", "10.64.1.2"),
        "add element inet briqyard internet_out { 10.64.1.2 }\n\
         add element inet briqyard internet_in { 10.64.1.2 }\n\
         add element inet briqyard dropped_port { 10.64.1.2 }\n\
         add element inet briqyard dropped_rate { 10.64.1.2 }\n\
         add element inet briqyard dropped_bandwidth { 10.64.1.2 }\n"
    );
    assert_eq!(
        counter_elements("delete", "10.64.1.2"),
        "delete element inet briqyard internet_out { 10.64.1.2 }\n\
         delete element inet briqyard internet_in { 10.64.1.2 }\n\
         delete element inet briqyard dropped_port { 10.64.1.2 }\n\
         delete element inet briqyard dropped_rate { 10.64.1.2 }\n\
         delete element inet briqyard dropped_bandwidth { 10.64.1.2 }\n"
    );
}

#[test]
fn counters_are_read_from_nft_json() {
    // What nft 1.1.6 prints for a counter set, read on the dev VM.
    let listed = br#"{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "internet_out", "table": "briqyard", "type": "ipv4_addr", "handle": 2, "elem": [{"elem": {"val": "10.64.1.2", "counter": {"packets": 6, "bytes": 504}}}, {"elem": {"val": "10.64.1.3", "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}"#;
    let out = set_counts(listed).unwrap();
    assert_eq!(
        out,
        HashMap::from([
            ("10.64.1.2".to_string(), (6, 504)),
            ("10.64.1.3".to_string(), (0, 0))
        ])
    );
    // An empty set has no `elem`.
    let empty = br#"{"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": "internet_in", "table": "briqyard", "type": "ipv4_addr", "handle": 3, "stmt": [{"counter": null}]}}]}"#;
    assert!(set_counts(empty).unwrap().is_empty());
    // A set without counters is an error, not zero.
    let bare = br#"{"nftables": [{"set": {"elem": [{"elem": {"val": "10.64.1.2"}}]}}]}"#;
    assert_eq!(
        set_counts(bare).unwrap_err().to_string(),
        "10.64.1.2: no counter"
    );
    assert!(set_counts(b"not json").is_err());
    // Each set to its field, bytes for the internet, packets for the drops; an address
    // missing from a set has zero there.
    let one = |ip: &str, packets, bytes| HashMap::from([(ip.to_string(), (packets, bytes))]);
    let sets = [
        out,
        one("10.64.1.2", 70, 9000),
        one("10.64.1.2", 1, 60),
        one("10.64.1.3", 10, 600),
        one("10.64.1.2", 57, 280980),
    ];
    assert_eq!(
        by_address(&sets),
        HashMap::from([
            (
                "10.64.1.2".to_string(),
                Counters {
                    internet_in: 9000,
                    internet_out: 504,
                    dropped: EgressDrops {
                        blocked_port: 1,
                        rate: 0,
                        bandwidth: 57
                    }
                }
            ),
            (
                "10.64.1.3".to_string(),
                Counters {
                    dropped: EgressDrops {
                        rate: 10,
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        ])
    );
}

#[test]
fn ports() {
    assert_eq!(
        daemon_ports("127.0.0.1:7420", "", "20000-29999").unwrap(),
        ["7420", "20000-29999"]
    );
    assert_eq!(
        daemon_ports("[::]:7420", "0.0.0.0:8080", "30000-31000").unwrap(),
        ["7420", "8080", "30000-31000"]
    );
    let err = daemon_ports("7420", "", "20000-29999").unwrap_err();
    assert_eq!(err.to_string(), "listen \"7420\": want address:port");
    let err = daemon_ports("127.0.0.1:7420", "8080", "20000-29999").unwrap_err();
    assert_eq!(err.to_string(), "ingress.http \"8080\": want address:port");
    for bad in ["20000", "0-10", "30-20", "a-b"] {
        let err = daemon_ports("127.0.0.1:7420", "", bad).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("ingress.tcp_ports {bad:?}: want \"lo-hi\"")
        );
    }
}

#[test]
fn sibling_state_is_linear_and_the_default_never_admits_it() {
    let strict = via();
    assert!(!strict.elements("add").contains("via_siblings"));
    let mut opted = strict.clone();
    let Policy::Via { siblings, .. } = &mut opted else {
        unreachable!()
    };
    *siblings = true;
    assert!(opted.elements("add").contains("via_siblings { 10.64.0.3 }"));
    let revoke = swap_elements(&opted, &strict);
    assert!(revoke.contains("delete element bridge briqyard via_siblings"));
    assert!(!revoke.contains("add element bridge briqyard via_siblings"));
    let sized = |count| {
        let mut rules = ruleset();
        rules.pins.clear();
        rules.members.clear();
        rules.policies.clear();
        for n in 2..count + 2 {
            let ip = format!("10.64.0.{n}");
            rules.pins.push((format!("bt{n:012x}"), ip.clone()));
            rules.members.push(("by0".into(), ip));
        }
        rules.render().len()
    };
    assert!(
        sized(128) < sized(64) * 2,
        "no source/destination membership matrix"
    );
}

#[test]
fn every_peer_allowance_follows_source_pins_and_both_forward_checks_return() {
    let text = ruleset().render();
    let prerouting = &text[text.rfind("chain prerouting").unwrap()..];
    for pin in [
        "iifname . ether saddr != @mac_pins drop",
        "iifname . arp saddr ether != @mac_pins drop",
        "iifname . ip saddr != @pins drop",
        "iifname . arp saddr ip != @pins drop",
    ] {
        assert!(prerouting.find(pin).unwrap() < prerouting.find("jump via_ipv4").unwrap());
    }
    assert!(
        text.contains("iifname \"bt*\" oifname \"bt*\" ip daddr @via_sources jump via_reply_ipv4")
    );
    assert!(text.contains("ip daddr . iifname @via_targets return"));
    let forward = &text
        [text.find("chain via_forward_ipv4").unwrap()..text.find("chain via_reply_ipv4").unwrap()];
    assert!(
        !forward.contains(" accept"),
        "a source allowance must not bypass the destination's policy"
    );
    assert!(forward.contains("meta obrname . ip daddr @members return"));
}

#[test]
fn an_attachment_has_one_batch_for_membership_pins_and_policy() {
    let script = attachment_elements("add", "btclient", "by1", "10.64.1.3", Some(&via()));
    for object in [
        " pins ",
        " mac_pins ",
        " members ",
        " via_sources ",
        " via_allowed ",
        " via_targets ",
    ] {
        assert!(script.contains(object));
    }
    assert!(script.contains("members { \"by1\" . 10.64.1.3 }"));
    assert!(script.contains("mac_pins { \"btclient\" . 06:b1:0a:40:01:03 }"));
}

#[test]
fn revocation_is_idempotent_without_swallowing_a_partial_batch_error() {
    let policy = open();
    let batch = attachment_elements(
        "delete",
        "btabcdef123456",
        "by0",
        policy.ip(),
        Some(&policy),
    );
    let first_delete = batch.find("delete ").unwrap();
    assert!(batch[..first_delete].contains("add element bridge briqyard pins"));
    assert!(batch[..first_delete].contains("add element bridge briqyard members"));
    assert!(batch[..first_delete].contains("add limit inet briqyard conn_"));
    assert!(batch[first_delete..].contains("delete limit inet briqyard conn_"));
    assert!(!batch[first_delete..].contains("add "));
}
