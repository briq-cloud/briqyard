//! Layers written into the directory a build extracts to (ADR 0039). The directory is held
//! open and every path of a layer is resolved by the kernel inside it: `openat2` with
//! `RESOLVE_IN_ROOT`, so `..` and symlinks, absolute ones included, never lead out of it, as
//! the guest will read them in its own root. Every write is an `*at` call on the directory
//! found, and the last name is never followed: a rewritten link replaces the link, not its
//! target. Linux only (`openat2`, Linux 5.6).

use anyhow::{anyhow, Context, Result};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Gid, Mode, OFlags, ResolveFlags, Uid};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// The root a layer is written into, open as a path.
struct Root(OwnedFd);

impl Root {
    fn open(path: &Path) -> Result<Self> {
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let fd = fs::open(path, flags, Mode::empty())
            .with_context(|| format!("open {}", path.display()))?;
        let root = Self(fd);
        // A kernel without openat2 is said once, not as every entry's ENOSYS.
        match root.dir("") {
            Err(Errno::NOSYS) => Err(anyhow!("image extraction needs openat2 (Linux 5.6)")),
            r => {
                r.with_context(|| format!("resolve {} in itself", path.display()))?;
                Ok(root)
            }
        }
    }

    /// Opens what `rel` resolves to inside the root, an absolute path or a link's target taken
    /// from the root and `..` stopping there.
    fn resolve(&self, rel: &str, flags: OFlags) -> rustix::io::Result<OwnedFd> {
        let rel = if rel.is_empty() { "." } else { rel };
        let (flags, how) = (flags | OFlags::CLOEXEC, ResolveFlags::IN_ROOT);
        // openat2(2): EAGAIN when a rename or a mount anywhere raced a `..` step, and "the
        // caller may choose to retry".
        let mut tries = 0;
        loop {
            match fs::openat2(&self.0, rel, flags, Mode::empty(), how) {
                Err(Errno::AGAIN) if tries < 64 => tries += 1,
                r => return r,
            }
        }
    }

    /// The directory `rel` resolves to.
    fn dir(&self, rel: &str) -> rustix::io::Result<OwnedFd> {
        self.resolve(rel, OFlags::PATH | OFlags::DIRECTORY)
    }

    /// The directory holding `rel`, made where missing, and `rel`'s last name. No name when
    /// `rel` ends in `..` or is empty: it is a directory then, whose mode and owner alone may
    /// be set.
    fn parent<'a>(&self, rel: &'a str) -> Result<(OwnedFd, Option<&'a str>)> {
        let (dir, name) = split(rel);
        let fd = self
            .make(&dir)
            .with_context(|| format!("make the directory of {rel}"))?;
        Ok((fd, name))
    }

    /// The directory `rel` resolves to, made one component at a time where missing.
    fn make(&self, rel: &str) -> Result<OwnedFd> {
        match self.dir(rel) {
            Err(Errno::NOENT) => {}
            r => return Ok(r?),
        }
        let parts = |p: &str| -> Vec<String> {
            p.split('/')
                .rev()
                .filter(|c| !c.is_empty())
                .map(String::from)
                .collect()
        };
        let mut pending = parts(rel);
        let (mut walked, mut dir, mut links) = (String::new(), self.dir("")?, 0);
        while let Some(part) = pending.pop() {
            let next = format!("{walked}{part}/");
            match self.dir(&next) {
                Err(Errno::NOENT) => {}
                r => {
                    (dir, walked) = (r?, next);
                    continue;
                }
            }
            match fs::mkdirat(&dir, part.as_str(), Mode::from_raw_mode(0o755)) {
                Ok(()) => (dir, walked) = (self.dir(&next)?, next),
                // A link to a directory not made yet (`sbin -> usr/sbin` before `usr/sbin`):
                // its target is walked instead, from the root when absolute.
                Err(Errno::EXIST) => {
                    links += 1;
                    if links > 40 {
                        return Err(anyhow!("{rel}: too many links"));
                    }
                    let target = fs::readlinkat(&dir, part.as_str(), Vec::new())?;
                    let target = target.to_string_lossy();
                    if target.starts_with('/') {
                        (dir, walked) = (self.dir("")?, String::new());
                    }
                    pending.extend(parts(&target));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(dir)
    }
}

/// `rel` as its directory and its last name; no name when it ends in `..` or is empty.
fn split(rel: &str) -> (String, Option<&str>) {
    let mut parts: Vec<&str> = rel
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    match parts.last() {
        Some(&last) if last != ".." => {
            parts.pop();
            (parts.join("/"), Some(last))
        }
        _ => (parts.join("/"), None),
    }
}

/// Removes `name` from `dir`, a directory with everything in it; a link is removed, never
/// followed.
fn remove(dir: BorrowedFd<'_>, name: &OsStr) -> rustix::io::Result<()> {
    match fs::unlinkat(dir, name, AtFlags::empty()) {
        Err(Errno::ISDIR) => {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            clear(&fs::openat(dir, name, flags, Mode::empty())?)?;
            fs::unlinkat(dir, name, AtFlags::REMOVEDIR)
        }
        r => r,
    }
}

/// Removes everything in the directory `d`, open for reading.
fn clear(d: &OwnedFd) -> rustix::io::Result<()> {
    let mut names = Vec::new();
    for e in fs::Dir::read_from(d)? {
        let n = e?.file_name().to_bytes().to_vec();
        if n != b"." && n != b".." {
            names.push(OsString::from(OsStr::from_bytes(&n)));
        }
    }
    for n in names {
        remove(d.as_fd(), &n)?;
    }
    Ok(())
}

/// A directory at `name` in `dir`, anything else there replaced, open as a path.
fn mkdir(dir: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    let real = fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|st| FileType::from_raw_mode(st.st_mode).is_dir());
    if !real {
        let _ = remove(dir.as_fd(), name.as_ref());
        fs::mkdirat(dir, name, Mode::from_raw_mode(0o700))?;
    }
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    fs::openat(dir, name, flags, Mode::empty())
}

/// A new regular file at `name` in `dir`, open for writing, whatever was there removed.
fn create(dir: &OwnedFd, name: &str) -> rustix::io::Result<std::fs::File> {
    let _ = remove(dir.as_fd(), name.as_ref());
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(fs::openat(dir, name, flags, Mode::from_raw_mode(0o600))?.into())
}

/// Sets the owner of `name` in `dir` (`.` for `dir` itself), never through a link; best effort,
/// as an unprivileged test cannot. A uid or gid of -1 is left as it is, as chown(2) reads it.
fn chown(dir: &OwnedFd, name: &str, uid: u32, gid: u32) {
    let (uid, gid) = (
        (uid != u32::MAX).then(|| Uid::from_raw(uid)),
        (gid != u32::MAX).then(|| Gid::from_raw(gid)),
    );
    let _ = fs::chownat(dir, name, uid, gid, AtFlags::SYMLINK_NOFOLLOW);
}

/// Owner, then mode (a chown clears the set-id bits) of the directory `d`.
fn set_dir(d: &OwnedFd, mode: u32, uid: u32, gid: u32) -> rustix::io::Result<()> {
    chown(d, ".", uid, gid);
    fs::chmodat(d, ".", Mode::from_raw_mode(mode), AtFlags::empty())
}

/// Applies one layer, read as it is decompressed: whiteouts remove, everything else is
/// extracted inside `root`.
pub fn apply_layer<R: Read>(root: &Path, media_type: &str, layer: R) -> Result<usize> {
    let reader: Box<dyn Read + '_> = if media_type.ends_with("gzip") {
        Box::new(flate2::read::GzDecoder::new(layer))
    } else if media_type.ends_with("zstd") {
        Box::new(zstd::Decoder::new(layer)?)
    } else {
        Box::new(layer)
    };
    extract(root, reader)
}

/// Writes a tar stream under `root`. Returns the number of entries written.
pub fn extract<R: Read>(root: &Path, r: R) -> Result<usize> {
    let root = Root::open(root)?;
    let mut archive = tar::Archive::new(r);
    let mut n = 0;
    // Hard links are made after every other entry, so their target exists; each is
    // resolved then, since a later entry may have replaced a directory of its path.
    let mut hardlinks: Vec<(String, String)> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        let clean = name.trim_start_matches('/').trim_end_matches('/');
        if clean.is_empty() || clean == "." {
            continue;
        }
        let base = clean.rsplit('/').next().unwrap_or(clean);
        if base == ".wh..wh..opq" {
            let dir = clean.trim_end_matches(".wh..wh..opq");
            if let Ok(d) = root.resolve(dir, OFlags::RDONLY | OFlags::DIRECTORY) {
                let _ = clear(&d);
            }
            continue;
        }
        if let Some(victim) = base.strip_prefix(".wh.") {
            let path = format!("{}{victim}", &clean[..clean.len() - base.len()]);
            if let (dir, Some(name)) = split(&path) {
                if let Ok(d) = root.dir(&dir) {
                    let _ = remove(d.as_fd(), name.as_ref());
                }
            }
            continue;
        }
        // The entry's own link name reads GNU long links and PAX `linkpath`; the header's
        // stops at 100 bytes.
        let link = entry
            .link_name()?
            .map(|p| p.into_owned())
            .unwrap_or_default();
        match entry.header().entry_type() {
            tar::EntryType::Link => {
                let target = link.to_string_lossy();
                hardlinks.push((
                    clean.to_string(),
                    target.trim_start_matches('/').to_string(),
                ));
                continue;
            }
            tar::EntryType::Directory
            | tar::EntryType::Regular
            | tar::EntryType::Continuous
            | tar::EntryType::Symlink => {}
            _ => continue,
        }
        if write_entry(&root, clean, &link, &mut entry)
            .with_context(|| format!("extract {clean}"))?
        {
            n += 1;
        }
    }
    for (path, target) in hardlinks {
        let (dir, Some(name)) = root.parent(&path)? else {
            continue;
        };
        // A link to a symlink links the symlink, as link(2) does.
        let (src_dir, Some(src_name)) = split(&target) else {
            continue;
        };
        let Ok(src) = root.dir(&src_dir) else {
            continue;
        };
        let _ = remove(dir.as_fd(), name.as_ref());
        if fs::linkat(&src, src_name, &dir, name, AtFlags::empty()).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

/// Writes a directory, a regular file or a symlink at `clean`. `false`: nothing to write, a
/// name that resolves to a directory (`a/..`) only sets a directory entry's mode.
fn write_entry<R: Read>(
    root: &Root,
    clean: &str,
    link: &Path,
    entry: &mut tar::Entry<R>,
) -> Result<bool> {
    let header = entry.header();
    let kind = header.entry_type();
    let mode = header.mode().unwrap_or(0o644) & 0o7777;
    let (uid, gid) = (
        header.uid().unwrap_or(0) as u32,
        header.gid().unwrap_or(0) as u32,
    );
    let mtime = header.mtime().unwrap_or(0);
    let (dir, name) = root.parent(clean)?;
    let Some(name) = name else {
        if kind == tar::EntryType::Directory {
            set_dir(&dir, mode, uid, gid)?;
            return Ok(true);
        }
        return Ok(false);
    };
    match kind {
        tar::EntryType::Directory => set_dir(&mkdir(&dir, name)?, mode, uid, gid)?,
        tar::EntryType::Symlink => {
            let _ = remove(dir.as_fd(), name.as_ref());
            // Kept as is: the guest resolves it inside its own root.
            fs::symlinkat(link, &dir, name)?;
            chown(&dir, name, uid, gid);
        }
        _ => {
            let mut f = create(&dir, name)?;
            std::io::copy(entry, &mut f)?;
            chown(&dir, name, uid, gid);
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime);
            let _ = f.set_modified(t);
        }
    }
    Ok(true)
}

/// Adds what every guest needs: the init, mount points, writable name files. A symlink a
/// layer left at one is replaced, never followed.
pub fn prepare_root(root: &Path, init: &Path) -> Result<()> {
    let root = Root::open(root)?;
    for d in ["proc", "sys", "dev", "run", "tmp", "etc", ".briqyard"] {
        let fd = mkdir(&root.0, d).with_context(|| format!("make /{d}"))?;
        if d == "tmp" {
            fs::chmodat(&fd, ".", Mode::from_raw_mode(0o1777), AtFlags::empty())?;
        }
    }
    let (dir, name) = root.parent(super::INIT_PATH)?;
    let name = name.context("the init's path has no name")?;
    let mut f = create(&dir, name).context("write the init")?;
    std::io::copy(&mut std::fs::File::open(init)?, &mut f).context("copy init")?;
    f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    // The init rewrites these at boot; a symlink (Debian's resolv.conf) or a missing file
    // would make that write land elsewhere or fail.
    let etc = mkdir(&root.0, "etc")?;
    for f in ["hosts", "resolv.conf", "hostname"] {
        let kept = fs::statat(&etc, f, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|st| !FileType::from_raw_mode(st.st_mode).is_symlink());
        if !kept {
            create(&etc, f).with_context(|| format!("write /etc/{f}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an archive with raw names: the tar crate refuses `..` and absolute links when
    /// writing, and those are what the extractor must survive.
    fn archive(entries: &[(&str, tar::EntryType, &str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, link, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_mode(0o755);
            h.set_size(body.len() as u64);
            {
                let g = h.as_gnu_mut().unwrap();
                g.name[..name.len()].copy_from_slice(name.as_bytes());
                g.linkname[..link.len()].copy_from_slice(link.as_bytes());
            }
            h.set_cksum();
            b.append(&h, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn extraction_stays_in_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let tar = archive(&[
            ("etc/", tar::EntryType::Directory, "", ""),
            ("etc/hello", tar::EntryType::Regular, "", "hi\n"),
            (
                "escape",
                tar::EntryType::Symlink,
                outside.path().to_str().unwrap(),
                "",
            ),
            ("escape/pwned", tar::EntryType::Regular, "", "x"),
            ("../../up", tar::EntryType::Regular, "", "y"),
            ("bin/sh", tar::EntryType::Regular, "", "#!"),
            ("bin/ash", tar::EntryType::Link, "bin/sh", ""),
            ("dev/null", tar::EntryType::Char, "", ""),
        ]);
        let n = extract(root.path(), &tar[..]).unwrap();
        assert!(n >= 5, "{n}");
        assert_eq!(
            std::fs::read_to_string(root.path().join("etc/hello")).unwrap(),
            "hi\n"
        );
        assert!(
            !outside.path().join("pwned").exists(),
            "written outside the root through a symlink"
        );
        assert!(root.path().join("up").exists());
        assert!(root.path().join("bin/ash").exists());
        assert!(
            std::fs::symlink_metadata(root.path().join("dev/null")).is_err(),
            "devices are skipped"
        );
    }

    #[test]
    fn a_name_ending_in_dotdot_stays_in_root() {
        // `x/../..` once resolved to `root/x/../..`, above the root: a directory entry
        // changed that directory's mode, a file entry or a whiteout removed it whole.
        for entry in [
            ("x/../../..", tar::EntryType::Directory, "", ""),
            ("y/../../..", tar::EntryType::Regular, "", "y"),
            ("../../.wh..", tar::EntryType::Regular, "", ""),
            ("a/..", tar::EntryType::Regular, "", "z"),
        ] {
            let base = tempfile::tempdir().unwrap();
            let root = base.path().join("a/b/c/root");
            std::fs::create_dir_all(&root).unwrap();
            for dir in ["a", "a/b", "a/b/c"] {
                std::fs::write(base.path().join(dir).join("keep"), "k").unwrap();
            }
            let b = base.path().join("a/b");
            std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o711)).unwrap();
            extract(
                &root,
                &archive(&[entry, ("etc/hello", tar::EntryType::Regular, "", "hi")])[..],
            )
            .unwrap();
            for dir in ["a", "a/b", "a/b/c"] {
                assert!(
                    base.path().join(dir).join("keep").exists(),
                    "{}: {dir} removed",
                    entry.0
                );
            }
            let mode = std::fs::metadata(&b).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o711, "{}: mode of a/b changed", entry.0);
            assert_eq!(
                std::fs::read_to_string(root.join("etc/hello")).unwrap(),
                "hi"
            );
        }
        let root = tempfile::tempdir().unwrap();
        let r = Root::open(root.path()).unwrap();
        let top = id(&r.0);
        for rel in ["..", "a/..", "a/b/../..", "../../x/..", "./.."] {
            let (dir, name) = r.parent(rel).unwrap();
            assert_eq!((id(&dir), name), (top, None), "{rel}");
        }
        let (dir, name) = r.parent("a/../b").unwrap();
        assert_eq!((id(&dir), name), (top, Some("b")));
    }

    #[test]
    fn a_hard_link_is_resolved_when_it_is_made() {
        // Hard links are made after the other entries. One resolved when read kept its
        // path through `a`, which a later entry turned into a link out of the root.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), "keep").unwrap();
        extract(
            root.path(),
            &archive(&[
                ("bin/sh", tar::EntryType::Regular, "", "#!"),
                ("a/victim", tar::EntryType::Link, "bin/sh", ""),
                (
                    "a",
                    tar::EntryType::Symlink,
                    outside.path().to_str().unwrap(),
                    "",
                ),
            ])[..],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(outside.path().join("victim")).unwrap(),
            "keep"
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_hard_link_to_a_link_out_of_the_root_stays_in_it() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), "keep").unwrap();
        let out = outside.path().join("f");
        extract(
            root.path(),
            &archive(&[
                ("out", tar::EntryType::Symlink, out.to_str().unwrap(), ""),
                ("copy", tar::EntryType::Link, "out", ""),
            ])[..],
        )
        .unwrap();
        // The source resolves inside the root, where nothing is: no link to the host file.
        let host = std::fs::metadata(&out).unwrap();
        assert_eq!(std::os::unix::fs::MetadataExt::nlink(&host), 1);
    }

    #[test]
    fn preparing_a_root_never_follows_its_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        for d in ["etc", "tmp", ".briqyard"] {
            let o = outside.path().join(d);
            std::fs::create_dir(&o).unwrap();
            std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::os::unix::fs::symlink(&o, root.path().join(d)).unwrap();
        }
        let init = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(init.path(), "init").unwrap();
        prepare_root(root.path(), init.path()).unwrap();
        for d in ["etc", "tmp", ".briqyard"] {
            let o = outside.path().join(d);
            assert_eq!(
                std::fs::read_dir(&o).unwrap().count(),
                0,
                "{d}: written outside"
            );
            let mode = std::fs::metadata(&o).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o700, "{d}: mode outside changed");
            assert!(std::fs::symlink_metadata(root.path().join(d))
                .unwrap()
                .is_dir());
        }
        assert_eq!(
            std::fs::read_to_string(root.path().join(".briqyard/init")).unwrap(),
            "init"
        );
        for f in ["etc/hosts", "etc/resolv.conf", "etc/hostname"] {
            assert!(root.path().join(f).is_file(), "{f}");
        }
    }

    #[test]
    fn a_long_link_target_is_kept_whole() {
        let target = format!("/{}/target", "d".repeat(150));
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "ln", &target).unwrap();
        let tar = b.into_inner().unwrap();
        let root = tempfile::tempdir().unwrap();
        extract(root.path(), &tar[..]).unwrap();
        assert_eq!(
            std::fs::read_link(root.path().join("ln")).unwrap(),
            Path::new(&target)
        );
    }

    #[test]
    fn whiteouts_of_links_remove_the_link_only() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), "keep").unwrap();
        extract(
            root.path(),
            &archive(&[
                ("data/f", tar::EntryType::Regular, "", "x"),
                ("ln", tar::EntryType::Symlink, "data", ""),
                (
                    "out",
                    tar::EntryType::Symlink,
                    outside.path().to_str().unwrap(),
                    "",
                ),
            ])[..],
        )
        .unwrap();
        extract(
            root.path(),
            &archive(&[
                (".wh.ln", tar::EntryType::Regular, "", ""),
                ("out/.wh..wh..opq", tar::EntryType::Regular, "", ""),
            ])[..],
        )
        .unwrap();
        assert!(std::fs::symlink_metadata(root.path().join("ln")).is_err());
        assert!(root.path().join("data/f").exists());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("f")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn rewriting_a_symlink_does_not_follow_it() {
        let root = tempfile::tempdir().unwrap();
        // Layer 1: merged usr: bin -> usr/bin, busybox, lzcat -> /bin/busybox.
        extract(
            root.path(),
            &archive(&[
                ("usr/bin/busybox", tar::EntryType::Regular, "", "BB"),
                ("bin", tar::EntryType::Symlink, "usr/bin", ""),
                ("usr/bin/lzcat", tar::EntryType::Symlink, "/bin/busybox", ""),
            ])[..],
        )
        .unwrap();
        // Layer 2 rewrites the same link: busybox must survive.
        extract(
            root.path(),
            &archive(&[("usr/bin/lzcat", tar::EntryType::Symlink, "/bin/busybox", "")])[..],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("usr/bin/busybox")).unwrap(),
            "BB"
        );
        assert!(std::fs::symlink_metadata(root.path().join("usr/bin/lzcat"))
            .unwrap()
            .file_type()
            .is_symlink());
        // A regular file written over a symlink replaces the link, not its target.
        extract(
            root.path(),
            &archive(&[("usr/bin/lzcat", tar::EntryType::Regular, "", "real")])[..],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("usr/bin/lzcat")).unwrap(),
            "real"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("usr/bin/busybox")).unwrap(),
            "BB"
        );
    }

    #[test]
    fn whiteouts() {
        let root = tempfile::tempdir().unwrap();
        extract(
            root.path(),
            &archive(&[
                ("a/x", tar::EntryType::Regular, "", "1"),
                ("a/y", tar::EntryType::Regular, "", "2"),
                ("b", tar::EntryType::Regular, "", "3"),
            ])[..],
        )
        .unwrap();
        extract(
            root.path(),
            &archive(&[
                ("a/.wh.x", tar::EntryType::Regular, "", ""),
                (".wh.b", tar::EntryType::Regular, "", ""),
            ])[..],
        )
        .unwrap();
        assert!(!root.path().join("a/x").exists());
        assert!(root.path().join("a/y").exists());
        assert!(!root.path().join("b").exists());
        extract(
            root.path(),
            &archive(&[
                ("a/.wh..wh..opq", tar::EntryType::Regular, "", ""),
                ("a/z", tar::EntryType::Regular, "", "4"),
            ])[..],
        )
        .unwrap();
        assert!(!root.path().join("a/y").exists());
        assert!(root.path().join("a/z").exists());
    }

    /// A layer is applied from a file, whatever its compression: the build never holds one
    /// in memory.
    #[test]
    fn a_layer_is_applied_from_a_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let tar = archive(&[("etc/hello", tar::EntryType::Regular, "", "hi\n")]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(&tar[..], 1).unwrap();
        for (name, media_type, bytes) in [
            ("plain", oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE, &tar),
            ("gz", oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE, &gz),
            ("zst", "application/vnd.oci.image.layer.v1.tar+zstd", &zst),
        ] {
            let layer = dir.path().join(name);
            std::fs::write(&layer, bytes).unwrap();
            let root = dir.path().join(format!("root-{name}"));
            std::fs::create_dir(&root).unwrap();
            let file: std::fs::File = std::fs::File::open(&layer).unwrap();
            assert_eq!(apply_layer(&root, media_type, file).unwrap(), 1, "{name}");
            assert_eq!(
                std::fs::read_to_string(root.join("etc/hello")).unwrap(),
                "hi\n",
                "{name}"
            );
        }
    }

    /// A directory's device and inode: which directory a descriptor or a path names.
    fn id(fd: &OwnedFd) -> (u64, u64) {
        let st = fs::fstat(fd).unwrap();
        (st.st_dev as u64, st.st_ino as u64)
    }

    fn id_of(p: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn a_path_resolves_through_links_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        for (link, target) in [("bin", "usr/bin"), ("abs", "/usr"), ("up", "../../usr/bin")] {
            std::os::unix::fs::symlink(target, root.path().join(link)).unwrap();
        }
        let r = Root::open(root.path()).unwrap();
        let bin = id_of(&root.path().join("usr/bin"));
        for rel in ["bin/x", "abs/bin/x", "up/x", "/abs/bin/x"] {
            let (dir, name) = r.parent(rel).unwrap();
            assert_eq!((id(&dir), name), (bin, Some("x")), "{rel}");
        }
    }

    #[test]
    fn dotdot_stops_at_the_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let r = Root::open(&root).unwrap();
        let (dir, name) = r.parent("../../etc/x").unwrap();
        assert_eq!((id(&dir), name), (id_of(&root.join("etc")), Some("x")));
        assert!(!base.path().join("etc").exists());
        let (dir, name) = r.parent("etc/../../..").unwrap();
        assert_eq!((id(&dir), name), (id_of(&root), None));
    }

    #[test]
    fn a_missing_directory_is_made() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/made/here", root.path().join("d")).unwrap();
        let r = Root::open(root.path()).unwrap();
        let (dir, name) = r.parent("p/q/r").unwrap();
        assert_eq!(
            (id(&dir), name),
            (id_of(&root.path().join("p/q")), Some("r"))
        );
        // A link to a directory not made yet: its target is made, inside the root.
        let (dir, name) = r.parent("d/f").unwrap();
        let here = root.path().join("made/here");
        assert_eq!((id(&dir), name), (id_of(&here), Some("f")));
        assert!(std::fs::symlink_metadata(root.path().join("d"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_relative_link_to_a_missing_directory_is_made_from_its_own() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/local")).unwrap();
        std::os::unix::fs::symlink("../sbin", root.path().join("usr/local/sbin")).unwrap();
        let r = Root::open(root.path()).unwrap();
        let (dir, name) = r.parent("usr/local/sbin/x").unwrap();
        let sbin = root.path().join("usr/sbin");
        assert_eq!((id(&dir), name), (id_of(&sbin), Some("x")));
        assert!(
            std::fs::symlink_metadata(root.path().join("usr/local/sbin"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn links_that_never_end_are_refused() {
        // Two links to each other: the kernel's own count (ELOOP) refuses it.
        let root = tempfile::tempdir().unwrap();
        for (link, target) in [("a", "b"), ("b", "a")] {
            std::os::unix::fs::symlink(target, root.path().join(link)).unwrap();
        }
        let r = Root::open(root.path()).unwrap();
        let err = format!("{:#}", r.parent("a/x").unwrap_err());
        assert!(err.contains("make the directory of a/x"), "{err}");
        // Each link through a directory not made yet: the kernel follows one link a call, and
        // the walk's own count stops it.
        for i in 0..41 {
            let target = format!("m{i}/../l{}", i + 1);
            std::os::unix::fs::symlink(target, root.path().join(format!("l{i}"))).unwrap();
        }
        let err = format!("{:#}", r.parent("l0/x").unwrap_err());
        assert!(err.contains("too many links"), "{err}");
    }
}
