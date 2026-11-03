//! Read-only proof of one actual jailed process; missing kernel evidence fails closed.
use super::*;

pub(super) fn process_credentials(status: &str, uid: u32, gid: u32) -> bool {
    fn row<'a>(status: &'a str, name: &str) -> Option<Vec<&'a str>> {
        let mut rows = status.lines().filter_map(|line| line.strip_prefix(name));
        let values = rows.next()?.split_whitespace().collect();
        rows.next().is_none().then_some(values)
    }
    let ids = |name, expected| {
        row(status, name).is_some_and(|values| {
            values.len() == 4
                && values
                    .iter()
                    .all(|value| value.parse::<u32>() == Ok(expected))
        })
    };
    ids("Uid:", uid)
        && ids("Gid:", gid)
        && row(status, "Groups:")
            .is_some_and(|values| values.iter().all(|value| value.parse::<u32>() == Ok(gid)))
}

pub(super) fn verify_process(id: &str, saved: &Incarnation, uid: u32, gid: u32) -> bool {
    if Incarnation::read(saved.pid).as_ref() != Some(saved)
        || super::vmm::machine_of(saved.pid).as_deref() != Some(id)
    {
        return false;
    }
    let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", saved.pid)) else {
        return false;
    };
    process_credentials(&status, uid, gid) && Incarnation::read(saved.pid).as_ref() == Some(saved)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_proof_requires_all_credential_ids_and_no_foreign_groups() {
        let valid = "Name:\tfirecracker\nUid:\t100002 100002 100002 100002\nGid:\t100002 100002 100002 100002\nGroups:\t100002\n";
        assert!(process_credentials(valid, 100002, 100002));
        assert!(process_credentials(
            &valid.replace("Groups:\t100002", "Groups:\t"),
            100002,
            100002
        ));
        for invalid in [
            valid.replace("Uid:\t100002", "Uid:\t0"),
            valid.replace("Gid:\t100002", "Gid:\t0"),
            valid.replace("Groups:\t100002", "Groups:\t100002 0"),
            valid.replace("100002 100002 100002 100002", "100002 100002 100002"),
            format!("{valid}Uid:\t100002 100002 100002 100002\n"),
            valid.replace("Groups:", "Missing:"),
        ] {
            assert!(!process_credentials(&invalid, 100002, 100002));
        }
    }
    #[test]
    fn absent_kernel_process_is_not_identity_proof() {
        let identity = Incarnation {
            pid: u32::MAX,
            start_ticks: 1,
            host_boot_id: "00000000-0000-0000-0000-000000000000".into(),
        };
        assert!(!verify_process("m_missing", &identity, 100002, 100002));
    }
}
