//! The root-private trust record: `/etc/briqyard-sealed/plan-reader/v1/<aud>/<reg-hash>/<serial>.json`.
//!
//! It is installed independently by the trusted root provisioning path and is never read or
//! rebuilt from a guard, a candidate, an offered Plan, a grant or an eligibility record. The
//! loader walks one pinned directory descriptor at a time, never a path string, so a symlink,
//! a hardlink, a foreign owner or a swapped directory refuses instead of being followed. A
//! missing or unreadable record fails the read; nothing substitutes for it.

use super::{io, PlanReadError};
use briqyard_api::execution::sealed::{
    canonical::{decode, MAX_MESSAGE_BYTES},
    objects::X,
    plan_pin::{TrustRecord, TrustSelector},
    prim::Ident,
    sig::PinnedKey,
};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat, CWD};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

const PRIVATE_ROOT: [&str; 3] = ["briqyard-sealed", "plan-reader", "v1"];

/// The only owner a trust directory or file may have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ownership {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

impl Ownership {
    pub(crate) const ROOT: Self = Self { uid: 0, gid: 0 };

    pub(crate) fn owns(self, stat: &Stat) -> bool {
        stat.st_uid == self.uid && stat.st_gid == self.gid
    }
}

/// The enrolled Rk/Bk for one operation, as the trust record names them.
#[derive(Debug)]
pub struct EnrolledTrust {
    record: TrustRecord,
    rk: PinnedKey,
    bk: PinnedKey,
}

impl EnrolledTrust {
    pub fn record(&self) -> &TrustRecord {
        &self.record
    }

    pub(crate) fn rk(&self) -> &PinnedKey {
        &self.rk
    }

    pub(crate) fn bk(&self) -> &PinnedKey {
        &self.bk
    }
}

/// Loads trust records beneath one anchored directory. Production anchors at `/` and walks
/// `/etc`; no environment, argument or host path selects another root.
pub struct TrustLoader {
    anchor: PathBuf,
    protected_ancestors: &'static [&'static str],
    ownership: Ownership,
}

struct Walk {
    chain: Vec<(OwnedFd, String, Stat)>,
}

impl TrustLoader {
    /// The fixed production loader. Only root may load root-private trust.
    pub fn system() -> Result<Self, PlanReadError> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(PlanReadError::Trust(
                "only root loads the plan reader trust",
            ));
        }
        Ok(Self {
            anchor: PathBuf::from("/"),
            protected_ancestors: &["etc"],
            ownership: Ownership::ROOT,
        })
    }

    /// Test scope only: a synthetic tree owned by the test's own user. It is not a production
    /// override and does not stand in for the qualified root-owned tree.
    #[cfg(test)]
    pub(crate) fn rooted_at(anchor: &Path, ownership: Ownership) -> Self {
        Self {
            anchor: anchor.to_path_buf(),
            protected_ancestors: &[],
            ownership,
        }
    }

    /// The enrolled keys for exactly this operation. The record's own `x` and `registered` must
    /// equal the caller's; a selector hit with another operation's record refuses.
    pub fn load(&self, x: &X, registered: &Ident) -> Result<EnrolledTrust, PlanReadError> {
        let selector = TrustSelector::new(x, registered);
        let bytes = self.read_file(&selector)?;
        let record = decode::<TrustRecord>(&bytes)
            .map_err(|_| PlanReadError::Trust("trust record is not canonical"))?;
        if record.x != *x || record.registered != *registered || record.selector() != selector {
            return Err(PlanReadError::Trust(
                "trust record names another operation or registration",
            ));
        }
        let (rk, bk) = record
            .pinned()
            .map_err(|_| PlanReadError::Trust("trust record holds a refused public key"))?;
        Ok(EnrolledTrust { record, rk, bk })
    }

    fn read_file(&self, selector: &TrustSelector) -> Result<Vec<u8>, PlanReadError> {
        let reg_hash = selector.reg_hash().to_string();
        let leaf = selector.file_name();
        let private: Vec<&str> = PRIVATE_ROOT
            .iter()
            .copied()
            .chain([selector.aud(), reg_hash.as_str()])
            .collect();

        let mut walk = Walk { chain: Vec::new() };
        let anchor = open_dir(CWD, &self.anchor, "open trust anchor")?;
        let anchor_stat = fstat(&anchor).map_err(|e| io("stat trust anchor", e.into()))?;
        self.protected(&anchor_stat)?;
        walk.chain.push((anchor, String::new(), anchor_stat));
        for name in self.protected_ancestors {
            let stat = walk.descend(name, "open protected trust ancestor")?;
            self.protected(&stat)?;
        }
        for name in private {
            let stat = walk.descend(name, "open private trust directory")?;
            self.private_dir(&stat)?;
        }

        let parent = &walk.chain.last().expect("anchor").0;
        let fd = openat(
            parent,
            leaf.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|e| io("open trust record", e.into()))?;
        let before = fstat(&fd).map_err(|e| io("stat trust record", e.into()))?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_nlink != 1
            || !self.ownership.owns(&before)
            || before.st_mode & 0o7777 != 0o600
            || before.st_size <= 0
            || before.st_size as u64 > MAX_MESSAGE_BYTES as u64
        {
            return Err(PlanReadError::Trust(
                "trust record is not a private single-link regular file",
            ));
        }
        let mut bytes = Vec::with_capacity(before.st_size as usize);
        File::from(
            fd.try_clone()
                .map_err(|e| io("duplicate trust record", e))?,
        )
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io("read trust record", e))?;
        let after = fstat(&fd).map_err(|e| io("restat trust record", e.into()))?;
        if bytes.len() as u64 != before.st_size as u64 || !same_file(&before, &after) {
            return Err(PlanReadError::Trust("trust record changed while read"));
        }
        let named = statat(parent, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| io("restat trust record name", e.into()))?;
        if !same_file(&before, &named) {
            return Err(PlanReadError::Trust("trust record was replaced while read"));
        }
        walk.still_names_the_same_directories()?;
        Ok(bytes)
    }

    fn protected(&self, stat: &Stat) -> Result<(), PlanReadError> {
        if self.ownership.owns(stat) && stat.st_mode & 0o022 == 0 {
            return Ok(());
        }
        Err(PlanReadError::Trust(
            "trust ancestry is foreign or writable by others",
        ))
    }

    fn private_dir(&self, stat: &Stat) -> Result<(), PlanReadError> {
        if self.ownership.owns(stat) && stat.st_mode & 0o7777 == 0o700 {
            return Ok(());
        }
        Err(PlanReadError::Trust(
            "trust directory is not private to its owner",
        ))
    }
}

impl Walk {
    fn descend(&mut self, name: &str, operation: &'static str) -> Result<Stat, PlanReadError> {
        let parent = &self.chain.last().expect("anchor").0;
        let fd = open_dir(parent, Path::new(name), operation)?;
        let stat = fstat(&fd).map_err(|e| io(operation, e.into()))?;
        self.chain.push((fd, name.to_string(), stat));
        Ok(stat)
    }

    fn still_names_the_same_directories(&self) -> Result<(), PlanReadError> {
        for pair in self.chain.windows(2) {
            let named = statat(&pair[0].0, pair[1].1.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| io("restat trust directory name", e.into()))?;
            if !same_node(&pair[1].2, &named) {
                return Err(PlanReadError::Trust(
                    "trust directory was replaced while read",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn open_dir(
    parent: impl std::os::fd::AsFd,
    path: &Path,
    operation: &'static str,
) -> Result<OwnedFd, PlanReadError> {
    openat(
        parent,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io(operation, e.into()))
}

/// The same inode with the same type, owner and mode: what a directory or socket name must keep.
pub(crate) fn same_node(a: &Stat, b: &Stat) -> bool {
    (a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode)
        == (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode)
}

/// The same node, link count, size and change times: an unmodified regular file.
fn same_file(a: &Stat, b: &Stat) -> bool {
    same_node(a, b)
        && (a.st_size, a.st_nlink) == (b.st_size, b.st_nlink)
        && (a.st_mtime, a.st_mtime_nsec, a.st_ctime, a.st_ctime_nsec)
            == (b.st_mtime, b.st_mtime_nsec, b.st_ctime, b.st_ctime_nsec)
}
