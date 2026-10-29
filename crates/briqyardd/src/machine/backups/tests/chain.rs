//! Chains: what is whole, what is pruned, what continues from what.

use super::*;

fn disk(name: &str, id: &str, from: Option<&str>) -> api::BackupDisk {
    api::BackupDisk {
        disk: name.into(),
        key: format!("k-{name}-{id}"),
        bytes: 1,
        from: from.map(String::from),
    }
}

/// A backup of the root disk, whole or from another.
fn b(id: &str, from: Option<&str>) -> api::Backup {
    api::Backup {
        id: id.into(),
        machine_id: "m_1".into(),
        namespace: "t".into(),
        name: "n".into(),
        created_at: Utc::now(),
        bytes: 1,
        incremental: from.is_some(),
        disks: vec![disk("root", id, from)],
        key_id: Some("k1".into()),
        machine: None,
        sealed: None,
        deletes_at: None,
    }
}

fn ids(bs: &[&api::Backup]) -> Vec<String> {
    bs.iter().map(|b| b.id.clone()).collect()
}

#[test]
fn backup_chains() {
    let all = vec![
        b("a", None),
        b("b", Some("a")),
        b("c", Some("b")),
        b("d", None),
    ];
    let keys = |t: &api::Backup| -> Vec<String> {
        backup_chain(&all, t, "root")
            .iter()
            .map(|d| d.key.clone())
            .collect()
    };
    assert_eq!(keys(&all[2]), vec!["k-root-a", "k-root-b", "k-root-c"]);
    assert_eq!(keys(&all[0]), vec!["k-root-a"]);
    assert_eq!(keys(&all[3]), vec!["k-root-d"]);
    assert!(backup_chain(&all, &all[2], "data").is_empty());
    // A base that is not in the store ends the chain where it is.
    let orphan = b("e", Some("zz"));
    assert_eq!(keys(&orphan), vec!["k-root-e"]);
    assert_eq!(
        newest_backup_snapshot(&[
            "fork-x".into(),
            "bk-20260101T000000.000Z".into(),
            "bk-20260102T000000.000Z".into()
        ]),
        Some("bk-20260102T000000.000Z".into())
    );
    assert_eq!(newest_backup_snapshot(&["fork-x".into()]), None);
    // A base is a snapshot of one of the machine's backups that holds that disk.
    assert!(in_store(&all, "bk-b", "root", "k1"));
    assert!(!in_store(&all, "bk-b", "data", "k1"));
    assert!(!in_store(&all, "bk-zz", "root", "k1"));
    // And sent raw under this pool's key: never over a stream in clear or another key's.
    assert!(!in_store(&all, "bk-b", "root", "k2"));
    let mut clear = all.clone();
    clear[1].key_id = None;
    assert!(!in_store(&clear, "bk-b", "root", "k1"));
}

#[test]
fn retention_keeps_the_newest_and_what_they_continue_from() {
    // keep 2: whole every second backup, the store between 2 and 3.
    let mut all = vec![b("1", None)];
    assert!(prune(&all, 2).is_empty());
    assert_eq!(chain_length(&all), 1);
    all.push(b("2", Some("1")));
    assert!(prune(&all, 2).is_empty());
    assert_eq!(chain_length(&all), 2, "the next one is whole");
    all.push(b("3", None));
    assert!(prune(&all, 2).is_empty(), "2 is kept and needs 1");
    assert_eq!(chain_length(&all), 1);
    all.push(b("4", Some("3")));
    assert_eq!(ids(&prune(&all, 2)), vec!["1", "2"]);
    // keep 1: every backup whole, the store holds one.
    let all = vec![b("1", None), b("2", None)];
    assert_eq!(ids(&prune(&all, 1)), vec!["1"]);
    // A base of either disk is kept.
    let mut two = b("2", None);
    two.disks.push(disk("data", "2", Some("1")));
    let all = vec![b("1", None), two, b("3", None)];
    assert!(prune(&all, 2).is_empty());
    assert_eq!(ids(&prune(&all, 1)), vec!["1", "2"]);
    // A chain with no whole backup (before schedules) counts whole.
    let all = vec![b("1", Some("0")), b("2", Some("1"))];
    assert_eq!(chain_length(&all), 2);
    assert_eq!(chain_length(&[]), 0);
}

#[test]
fn what_continues_from_a_backup() {
    let all = vec![
        b("1", None),
        b("2", Some("1")),
        b("3", Some("2")),
        b("4", None),
        b("5", Some("4")),
    ];
    assert_eq!(dependents(&all, 0), vec![1, 2]);
    assert_eq!(dependents(&all, 1), vec![2]);
    assert_eq!(dependents(&all, 3), vec![4]);
    assert!(dependents(&all, 4).is_empty());
}
