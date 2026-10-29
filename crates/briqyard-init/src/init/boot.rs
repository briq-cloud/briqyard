use super::*;

pub(super) fn mount_base() {
    let nosuid = MsFlags::MS_NOSUID;
    let noexec = MsFlags::MS_NOEXEC;
    let nodev = MsFlags::MS_NODEV;
    let mounts: &[(&str, &str, &str, MsFlags, &str)] = &[
        ("proc", "/proc", "proc", nosuid | noexec | nodev, ""),
        ("sysfs", "/sys", "sysfs", nosuid | noexec | nodev, ""),
        ("devtmpfs", "/dev", "devtmpfs", nosuid, "mode=0755"),
        ("tmpfs", "/run", "tmpfs", nosuid | nodev, "mode=0755"),
        ("tmpfs", "/tmp", "tmpfs", nosuid | nodev, "mode=1777"),
    ];
    for (src, dst, fstype, flags, data) in mounts {
        let _ = fs::create_dir_all(dst);
        let _ = mount(Some(*src), *dst, Some(*fstype), *flags, Some(*data));
    }
    // What an init is expected to add to devtmpfs: bash's `<(...)` opens /dev/fd/N.
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        let _ = std::os::unix::fs::symlink(target, link);
    }
    let _ = fs::create_dir_all("/dev/pts");
    let _ = mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        nosuid | noexec,
        Some("mode=0620,gid=5,ptmxmode=666"),
    );
    let _ = fs::create_dir_all("/dev/shm");
    let _ = mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        nosuid | nodev,
        Some("mode=1777"),
    );
    let _ = fs::create_dir_all("/sys/fs/cgroup");
    let _ = mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        nosuid | noexec | nodev,
        Some(""),
    );
    let _ = fs::create_dir_all("/dev/mqueue");
    let _ = mount(
        Some("mqueue"),
        "/dev/mqueue",
        Some("mqueue"),
        nosuid | noexec | nodev,
        Some(""),
    );
}

#[derive(Debug)]
pub(super) struct BootFile {
    path: String,
    mode: u32,
    data: Vec<u8>,
}

/// Reads the raw tar on the config device.
pub(super) fn read_config_drive() -> Result<(Config, Vec<BootFile>)> {
    let f = fs::File::open(CONFIG_DEVICE).context(CONFIG_DEVICE)?;
    read_config_archive(std::io::BufReader::with_capacity(1 << 20, f))
}

/// Reads the config drive's tar: `config.json`, then the boot files under `files/`, whose
/// mode comes from the tar header unless the config names one.
pub(super) fn read_config_archive<R: Read>(r: R) -> Result<(Config, Vec<BootFile>)> {
    let mut archive = tar::Archive::new(r);
    let mut cfg: Option<Config> = None;
    let mut files = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        if name == guest::CONFIG_NAME {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            cfg = Some(serde_json::from_str(&s).context("config.json")?);
        } else if let Some(rest) = name.strip_prefix(guest::FILES_PREFIX) {
            if entry.header().entry_type().is_file() {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                files.push(BootFile {
                    path: format!("/{rest}"),
                    mode: entry.header().mode().unwrap_or(0o644),
                    data,
                });
            }
        }
    }
    let cfg = cfg.ok_or_else(|| anyhow!("no config.json on the config drive"))?;
    for f in &mut files {
        if let Some(m) = cfg.files.iter().find(|m| m.path == f.path) {
            if m.mode != 0 {
                f.mode = m.mode;
            }
        }
    }
    Ok((cfg, files))
}

/// Mounts the data volumes; a fresh one gets the image directory's owner and content, as
/// Docker does for a named volume. An ext4 volume is mounted with `discard`, so what the guest
/// deletes goes back to the host's pool (ADR 0037), and grown to its disk (ADR 0040).
pub(super) fn setup_mounts(cfg: &Config) -> Result<()> {
    for m in &cfg.mounts {
        let path = Path::new(&m.path);
        let seed = stage_mount_point(path)?;
        let fstype = if m.fstype.is_empty() {
            "ext4"
        } else {
            &m.fstype
        };
        mount(
            Some(m.device.as_str()),
            path,
            Some(fstype),
            MsFlags::MS_NOATIME,
            (fstype == "ext4").then_some("discard"),
        )
        .with_context(|| format!("mount {} on {}", m.device, m.path))?;
        if fstype == "ext4" {
            match grow_filesystem(&m.device, path) {
                Ok(Some((was, now))) => log!("volume {}: grown from {was} to {now} MB", m.path),
                Ok(None) => {}
                // The volume serves at the size it had; the next boot tries again.
                Err(e) => log!("volume {}: not grown: {e:#}", m.path),
            }
        }
        seed_mount_point(path, seed);
    }
    Ok(())
}

nix::ioctl_write_ptr!(ext4_resize_fs, b'f', 16, u64);

/// Grows the ext4 filesystem mounted at `path` to the end of `device` (ADR 0040): the disk
/// grows on the host, the filesystem here, at the next boot. The kernel grows a mounted
/// filesystem itself (`EXT4_IOC_RESIZE_FS`, what `resize2fs` asks of one), so the image needs
/// no tool, and it returns at once when the filesystem fills the device already. The sizes
/// before and after, in MB, when it grew.
pub(super) fn grow_filesystem(device: &str, path: &Path) -> Result<Option<(u64, u64)>> {
    use std::io::{Seek, SeekFrom};
    let bytes = fs::File::open(device)
        .and_then(|mut d| d.seek(SeekFrom::End(0)))
        .with_context(|| format!("size of {device}"))?;
    let statvfs = || nix::sys::statvfs::statvfs(path).context("statvfs");
    let mb = |st: &nix::sys::statvfs::Statvfs| (st.blocks() * st.fragment_size()) >> 20;
    let st = statvfs()?;
    let blocks: u64 = bytes / st.fragment_size();
    let dir = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    // SAFETY: the ioctl reads one u64 from the pointer, which outlives the call.
    unsafe { ext4_resize_fs(dir.as_raw_fd(), &blocks) }
        .with_context(|| format!("EXT4_IOC_RESIZE_FS to {blocks} blocks"))?;
    let (was, now) = (mb(&st), mb(&statvfs()?));
    Ok((now > was).then_some((was, now)))
}

/// What the image had at a mount path, kept aside while the volume is mounted over it.
pub(super) struct Seed {
    /// The image directory's metadata, when there was one.
    had: Option<fs::Metadata>,
    /// Where its content was moved.
    staging: Option<PathBuf>,
}

/// Moves what the image has at `path` aside and makes an empty directory to mount on.
pub(super) fn stage_mount_point(path: &Path) -> Result<Seed> {
    let had = fs::metadata(path).ok();
    let mut staging: Option<PathBuf> = None;
    if had.is_some() {
        let s = PathBuf::from(format!("{}.briqyard-seed", path.display()));
        let _ = fs::rename(path, &s);
        staging = Some(s);
    }
    fs::create_dir_all(path)?;
    Ok(Seed { had, staging })
}

/// After the mount: a fresh volume gets the image directory's owner, mode and content; the
/// staged copy goes either way.
pub(super) fn seed_mount_point(path: &Path, seed: Seed) {
    if is_empty_volume(path) {
        // A fresh ext4 has lost+found; a database refuses a data directory that is "not
        // empty". Docker's named volumes are plain directories, so match that: fsck makes
        // the directory again if it ever needs it.
        let _ = fs::remove_dir(path.join("lost+found"));
        if let Some(meta) = &seed.had {
            let _ = nix::unistd::chown(path, Some(meta.uid().into()), Some(meta.gid().into()));
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() & 0o7777));
            if let Some(s) = &seed.staging {
                let _ = copy_tree(s, path);
            }
        }
    }
    if let Some(s) = seed.staging {
        let _ = fs::remove_dir_all(s);
    }
}

pub(super) fn is_empty_volume(path: &Path) -> bool {
    match fs::read_dir(path) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .all(|e| e.file_name() == "lost+found"),
        Err(_) => false,
    }
}

pub(super) fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let target = dst.join(entry.file_name());
        let ft = meta.file_type();
        if ft.is_dir() {
            fs::create_dir_all(&target)?;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(meta.mode() & 0o7777));
            let _ = nix::unistd::chown(&target, Some(meta.uid().into()), Some(meta.gid().into()));
            copy_tree(&entry.path(), &target)?;
        } else if ft.is_symlink() {
            let l = fs::read_link(entry.path())?;
            let _ = std::os::unix::fs::symlink(l, &target);
            let _ = std::os::unix::fs::lchown(&target, Some(meta.uid()), Some(meta.gid()));
        } else if ft.is_file() {
            fs::copy(entry.path(), &target)?;
            let _ = nix::unistd::chown(&target, Some(meta.uid().into()), Some(meta.gid().into()));
        }
    }
    Ok(())
}

pub(super) fn write_files(files: &[BootFile]) -> Result<()> {
    write_files_under(Path::new("/"), files)
}

/// Writes the boot files, each at its absolute path under `root`.
pub(super) fn write_files_under(root: &Path, files: &[BootFile]) -> Result<()> {
    for f in files {
        let target = root.join(f.path.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &f.data).with_context(|| f.path.clone())?;
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(file_mode(f.mode)));
    }
    Ok(())
}

/// The mode a file is written with: 0644 when none was given, else the permission bits.
pub(super) fn file_mode(mode: u32) -> u32 {
    if mode & 0o777 == 0 {
        0o644
    } else {
        mode & 0o7777
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::init::testutil::*;

    // --- the config drive ---

    fn config_json() -> String {
        serde_json::to_string(&Config {
            hostname: "db".into(),
            ip: "10.64.1.2/24".into(),
            gateway: "10.64.1.1".into(),
            dns: vec!["10.64.1.1".into()],
            entrypoint: vec!["/bin/sh".into()],
            cmd: vec!["-c".into(), "true".into()],
            files: vec![
                guest::FileMeta {
                    path: "/etc/app.conf".into(),
                    mode: 0o600,
                },
                guest::FileMeta {
                    path: "/bin/run.sh".into(),
                    mode: 0,
                },
            ],
            ..Default::default()
        })
        .unwrap()
    }

    fn tar_with(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data, mode) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append_data(&mut h, name, &data[..]).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn config_archive_parses_config_and_files() {
        let mut b = tar::Builder::new(Vec::new());
        let cfg = config_json();
        let mut h = tar::Header::new_gnu();
        h.set_size(cfg.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, guest::CONFIG_NAME, cfg.as_bytes())
            .unwrap();
        // A directory entry under files/ is not a file: skipped.
        let mut d = tar::Header::new_gnu();
        d.set_entry_type(tar::EntryType::Directory);
        d.set_size(0);
        d.set_mode(0o755);
        d.set_cksum();
        b.append_data(&mut d, "files/etc", &[][..]).unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(4);
        f.set_mode(0o644);
        f.set_cksum();
        b.append_data(&mut f, "files/etc/app.conf", &b"k=v\n"[..])
            .unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(2);
        f.set_mode(0o755);
        f.set_cksum();
        b.append_data(&mut f, "files/bin/run.sh", &b"#!"[..])
            .unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(1);
        f.set_mode(0o600);
        f.set_cksum();
        b.append_data(&mut f, "other/ignored", &b"x"[..]).unwrap();
        let tar = b.into_inner().unwrap();

        let (cfg, files) = read_config_archive(&tar[..]).unwrap();
        assert_eq!(cfg.hostname, "db");
        assert_eq!(cfg.entrypoint, vec!["/bin/sh"]);
        assert_eq!(cfg.cmd, vec!["-c", "true"]);
        assert_eq!(
            files.len(),
            2,
            "the directory and the stray entry are not boot files"
        );
        // The config's mode wins over the tar header; a zero in the config keeps the header's.
        assert_eq!(files[0].path, "/etc/app.conf");
        assert_eq!(files[0].mode, 0o600);
        assert_eq!(files[0].data, b"k=v\n");
        assert_eq!(files[1].path, "/bin/run.sh");
        assert_eq!(files[1].mode, 0o755);
        assert_eq!(files[1].data, b"#!");
    }

    #[test]
    fn config_archive_without_config_or_with_bad_json() {
        let tar = tar_with(&[("files/etc/x", b"1", 0o644)]);
        let e = read_config_archive(&tar[..]).unwrap_err();
        assert!(e.to_string().contains("no config.json"), "{e:#}");
        let tar = tar_with(&[(guest::CONFIG_NAME, b"{not json", 0o644)]);
        let e = read_config_archive(&tar[..]).unwrap_err();
        assert!(format!("{e:#}").contains("config.json"), "{e:#}");
        // Not a tar at all.
        assert!(read_config_archive(&b"hello"[..]).is_err());
    }

    #[test]
    fn config_archive_file_mode_from_header_when_config_is_silent() {
        let cfg = serde_json::to_string(&Config::default()).unwrap();
        let tar = tar_with(&[
            (guest::CONFIG_NAME, cfg.as_bytes(), 0o644),
            ("files/opt/a", b"a", 0o640),
            ("files/opt/b", b"b", 0),
        ]);
        let (_, files) = read_config_archive(&tar[..]).unwrap();
        assert_eq!(files[0].mode, 0o640);
        assert_eq!(
            files[1].mode, 0,
            "written as 0644 later, see write_files_under"
        );
    }

    #[test]
    fn boot_files_written_with_their_modes() {
        let root = tempfile::tempdir().unwrap();
        let files = vec![
            BootFile {
                path: "/etc/app/app.conf".into(),
                mode: 0o600,
                data: b"k=v\n".to_vec(),
            },
            BootFile {
                path: "/bin/run.sh".into(),
                mode: 0,
                data: b"#!/bin/sh\n".to_vec(),
            },
            BootFile {
                path: "/setuid".into(),
                mode: 0o4755,
                data: vec![],
            },
            BootFile {
                path: "/extra-bits".into(),
                mode: 0o10644,
                data: vec![],
            },
        ];
        write_files_under(root.path(), &files).unwrap();
        let mode = |p: &str| fs::metadata(root.path().join(p)).unwrap().mode() & 0o7777;
        assert_eq!(
            fs::read(root.path().join("etc/app/app.conf")).unwrap(),
            b"k=v\n"
        );
        assert_eq!(mode("etc/app/app.conf"), 0o600);
        assert_eq!(mode("bin/run.sh"), 0o644, "no mode means 0644");
        assert_eq!(mode("setuid"), 0o4755, "setuid is kept");
        assert_eq!(
            mode("extra-bits"),
            0o644,
            "only the permission bits are kept"
        );
        // Written again at the next boot: the content is replaced.
        let again = vec![BootFile {
            path: "/bin/run.sh".into(),
            mode: 0o755,
            data: b"new".to_vec(),
        }];
        write_files_under(root.path(), &again).unwrap();
        assert_eq!(fs::read(root.path().join("bin/run.sh")).unwrap(), b"new");
        assert_eq!(mode("bin/run.sh"), 0o755);
    }

    #[test]
    fn file_modes() {
        assert_eq!(file_mode(0), 0o644);
        assert_eq!(file_mode(0o600), 0o600);
        assert_eq!(
            file_mode(0o4000),
            0o644,
            "no permission bits at all means the default"
        );
        assert_eq!(file_mode(0o100755), 0o755, "the file type bits are dropped");
    }

    // --- the volume ---

    #[test]
    fn a_filesystem_that_cannot_grow_is_an_error_not_a_failed_boot() {
        // Not ext4, or not root: the kernel refuses, and the caller logs it and boots on.
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("dev");
        std::fs::write(&dev, vec![0u8; 1 << 20]).unwrap();
        let err = grow_filesystem(dev.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("EXT4_IOC_RESIZE_FS to "),
            "{err:#}"
        );
        let err = grow_filesystem("/nonexistent", dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("size of /nonexistent"),
            "{err:#}"
        );
    }

    fn names(p: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn fresh_volume_is_seeded_from_the_image_directory() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("var/lib/app");
        fs::create_dir_all(data.join("sub")).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o750)).unwrap();
        write(&data.join("seed.txt"), b"seed", 0o640);
        write(&data.join("sub/deep.txt"), b"deep", 0o600);
        std::os::unix::fs::symlink("seed.txt", data.join("link")).unwrap();

        let seed = stage_mount_point(&data).unwrap();
        // The image's content is aside and an empty directory waits for the mount.
        let staging = root.path().join("var/lib/app.briqyard-seed");
        assert_eq!(seed.staging.as_deref(), Some(staging.as_path()));
        assert!(seed.had.is_some());
        assert!(names(&data).is_empty());
        assert_eq!(names(&staging), ["link", "seed.txt", "sub"]);

        // What a mount of a fresh ext4 leaves there.
        fs::create_dir(data.join("lost+found")).unwrap();
        seed_mount_point(&data, seed);

        assert_eq!(
            names(&data),
            ["link", "seed.txt", "sub"],
            "lost+found is gone"
        );
        assert_eq!(fs::read(data.join("seed.txt")).unwrap(), b"seed");
        assert_eq!(fs::read(data.join("sub/deep.txt")).unwrap(), b"deep");
        assert_eq!(
            fs::read_link(data.join("link")).unwrap(),
            Path::new("seed.txt")
        );
        assert_eq!(fs::metadata(&data).unwrap().mode() & 0o7777, 0o750);
        assert_eq!(
            fs::metadata(data.join("sub/deep.txt")).unwrap().mode() & 0o7777,
            0o600
        );
        assert!(!staging.exists(), "the staged copy is removed");
    }

    #[test]
    fn used_volume_keeps_its_content() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        write(&data.join("image.txt"), b"image", 0o644);
        let seed = stage_mount_point(&data).unwrap();
        // The volume already has data: nothing is seeded over it.
        fs::create_dir(data.join("lost+found")).unwrap();
        write(&data.join("PG_VERSION"), b"17", 0o600);
        seed_mount_point(&data, seed);
        assert_eq!(names(&data), ["PG_VERSION", "lost+found"]);
        assert!(!root.path().join("data.briqyard-seed").exists());
    }

    #[test]
    fn mount_point_the_image_does_not_have() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("new/mnt");
        let seed = stage_mount_point(&data).unwrap();
        assert!(seed.had.is_none());
        assert!(seed.staging.is_none());
        assert!(data.is_dir(), "made so the mount has somewhere to go");
        fs::create_dir(data.join("lost+found")).unwrap();
        seed_mount_point(&data, seed);
        assert!(
            names(&data).is_empty(),
            "lost+found is removed on a fresh volume"
        );
    }

    #[test]
    fn empty_volume() {
        let root = tempfile::tempdir().unwrap();
        assert!(is_empty_volume(root.path()));
        fs::create_dir(root.path().join("lost+found")).unwrap();
        assert!(
            is_empty_volume(root.path()),
            "only lost+found counts as empty"
        );
        write(&root.path().join("x"), b"", 0o644);
        assert!(!is_empty_volume(root.path()));
        assert!(
            !is_empty_volume(&root.path().join("missing")),
            "unreadable is not empty"
        );
    }

    #[test]
    fn copy_tree_keeps_modes_and_links() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        let dst = root.path().join("dst");
        fs::create_dir_all(src.join("a/b")).unwrap();
        fs::set_permissions(src.join("a"), fs::Permissions::from_mode(0o700)).unwrap();
        write(&src.join("a/b/f"), b"f", 0o755);
        std::os::unix::fs::symlink("/nowhere", src.join("dangling")).unwrap();
        fs::create_dir(&dst).unwrap();
        copy_tree(&src, &dst).unwrap();
        assert_eq!(fs::metadata(dst.join("a")).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(fs::read(dst.join("a/b/f")).unwrap(), b"f");
        assert_eq!(
            fs::metadata(dst.join("a/b/f")).unwrap().mode() & 0o7777,
            0o755
        );
        assert_eq!(
            fs::read_link(dst.join("dangling")).unwrap(),
            Path::new("/nowhere")
        );
        assert!(copy_tree(&root.path().join("missing"), &dst).is_err());
    }
}
