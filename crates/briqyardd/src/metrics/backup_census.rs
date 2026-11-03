//! Fixed scalar observations only. No identities, object keys, metadata or store access.
use briqyard_api::metrics::family;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub finished_at: i64,
    pub enumeration_complete: bool,
    pub metadata_complete: bool,
    pub objects: u64,
    pub records: u64,
    pub malformed: u64,
    pub read_failures: u64,
    pub missing_streams: u64,
    pub size_mismatches: u64,
    pub unresolved_chains: u64,
    pub unreferenced_streams: u64,
    pub local_owners: u64,
    pub unresolved_owners: u64,
    pub local_activity: bool,
    pub failed: bool,
}

pub fn render(out: &mut String, s: &Snapshot) {
    for (name, help, value) in [
        (
            "finished_timestamp_seconds",
            "Last attempt settlement time; zero before observation.",
            s.finished_at.max(0) as u64,
        ),
        (
            "enumeration_complete",
            "The last bounded backups prefix listing reached exhaustion; not atomic.",
            u64::from(s.enumeration_complete),
        ),
        (
            "metadata_complete",
            "Observed metadata and stream references passed bounded checks; no content authentication.",
            u64::from(s.metadata_complete),
        ),
        (
            "objects",
            "Objects observed in the bounded listing.",
            s.objects,
        ),
        (
            "records",
            "Strictly validated metadata records observed.",
            s.records,
        ),
        (
            "malformed",
            "Malformed paths or records observed.",
            s.malformed,
        ),
        (
            "read_failures",
            "Metadata reads missing, changed, oversized or failed.",
            s.read_failures,
        ),
        (
            "missing_streams",
            "Record stream references absent from the observed listing; races possible.",
            s.missing_streams,
        ),
        (
            "size_mismatches",
            "Stream lengths differing from metadata in this observation.",
            s.size_mismatches,
        ),
        (
            "unresolved_chains",
            "Disk chains whose transitive bases could not be validated.",
            s.unresolved_chains,
        ),
        (
            "unreferenced_streams",
            "Observed streams without a validated record reference; publication may be in flight.",
            s.unreferenced_streams,
        ),
        (
            "local_owners",
            "Records with a matching local machine, retained holder or admitted job owner.",
            s.local_owners,
        ),
        (
            "unresolved_owners",
            "Records without a matching observed local owner; never proof of orphanhood.",
            s.unresolved_owners,
        ),
        (
            "local_activity",
            "Backup jobs overlapped this observation; other races remain possible.",
            u64::from(s.local_activity),
        ),
        (
            "failed",
            "Last attempt failed or exceeded its runtime budget.",
            u64::from(s.failed),
        ),
        (
            "global_ownership_qualified",
            "Always zero: no atomic all-host owner authority.",
            0,
        ),
        (
            "deletion_qualified",
            "Always zero: observations never authorize deletion.",
            0,
        ),
    ] {
        family(
            out,
            &format!("briqyard_backup_census_{name}"),
            "gauge",
            help,
            vec![(String::new(), value.to_string())],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_rendering_never_qualify_ownership_or_deletion() {
        let mut out = String::new();
        render(&mut out, &Snapshot::default());
        assert!(out.contains("briqyard_backup_census_global_ownership_qualified 0"));
        assert!(out.contains("briqyard_backup_census_deletion_qualified 0"));
        assert!(out.contains("briqyard_backup_census_metadata_complete 0"));
        assert!(!out.contains("machine="));
        assert!(!out.contains("namespace="));
        assert!(!out.contains("key_id="));
    }
}
