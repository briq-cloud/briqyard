//! Opt-in native stream qualification. The operator owns pool provisioning and teardown.
use super::*;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(30);
const PAYLOAD: usize = 4 << 20;
const MAX_STREAM: u64 = 8 << 20;

fn scope(parent: &str, nonce: &str) -> Result<String> {
    if !matches!(nonce.len(), 24 | 32)
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(anyhow!(
            "fixture nonce must be 24 or 32 lowercase hex characters"
        ));
    }
    let pool = format!("bqown-{nonce}");
    if parent != format!("{pool}/fixture") {
        return Err(anyhow!(
            "fixture must be the exact nonce-bound child of a separate test pool"
        ));
    }
    Ok(pool)
}
fn input(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("required fixture input {name} is missing"))
}
fn number(name: &str) -> Result<u64> {
    let value = input(name)?.parse::<u64>().context("fixture integer")?;
    if value == 0 {
        return Err(anyhow!("fixture identity must be positive"));
    }
    Ok(value)
}
fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
        return Err(anyhow!("fixture file ownership/type/mode refused"));
    }
    Ok(file)
}
fn same_file(file: &File, path: &Path) -> Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if !named.is_file()
        || held.uid() != 0
        || held.gid() != 0
        || held.mode() & 0o777 != 0o600
        || held.nlink() != 1
        || (held.dev(), held.ino(), held.len()) != (named.dev(), named.ino(), named.len())
    {
        return Err(anyhow!("fixture named/held identity changed"));
    }
    Ok(())
}
async fn native(z: &Zfs, tool: &str, args: &[&str]) -> Result<String> {
    let mut command = Command::new(tool);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped());
    let bytes = tokio::time::timeout(
        LIMIT,
        z.owned(command, "fixture identity query".into(), false, |child| {
            let stdout = child.stdout.take().expect("piped");
            async move { owned::read_answer(stdout).await }
        }),
    )
    .await
    .context("fixture identity query unresolved")??;
    String::from_utf8(bytes).context("fixture query encoding")
}
struct Fixture {
    z: Zfs,
    parent: String,
    guid: u64,
    pool: String,
    pool_guid: u64,
    vdev_path: PathBuf,
    vdev: File,
    directory: File,
    _lease: File,
    mounts: PathBuf,
    children: Vec<(String, u64)>,
}
impl Fixture {
    async fn open() -> Result<Self> {
        if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
            return Err(anyhow!("native fixture requires Linux root"));
        }
        let parent = input("BRIQYARD_OWNED_ZFS_PARENT")?;
        let nonce = input("BRIQYARD_OWNED_ZFS_NONCE")?;
        let pool = scope(&parent, &nonce)?;
        let guid = number("BRIQYARD_OWNED_ZFS_PARENT_GUID")?;
        let pool_guid = number("BRIQYARD_OWNED_ZFS_POOL_GUID")?;
        let vdev_path = PathBuf::from(input("BRIQYARD_OWNED_ZFS_VDEV")?);
        if !vdev_path.is_absolute()
            || vdev_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(anyhow!("fixture vdev path refused"));
        }
        let directory = vdev_path.parent().context("fixture directory")?;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o700
            || directory.file_name().and_then(|n| n.to_str()) != Some(nonce.as_str())
        {
            return Err(anyhow!("fixture directory refused"));
        }
        let directory_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(directory)?;
        let vdev = private_file(&vdev_path)?;
        let m = vdev.metadata()?;
        if m.dev() != number("BRIQYARD_OWNED_ZFS_VDEV_DEV")?
            || m.ino() != number("BRIQYARD_OWNED_ZFS_VDEV_INO")?
            || !((64_u64 << 20)..=(2_u64 << 30)).contains(&m.len())
        {
            return Err(anyhow!("fixture backing-file identity/size refused"));
        }
        let lease_fd: i32 = input("BRIQYARD_OWNED_ZFS_LEASE_FD")?
            .parse()
            .context("fixture lease fd")?;
        if lease_fd < 3 {
            return Err(anyhow!("fixture lease fd refused"));
        }
        let duplicate = unsafe { libc::fcntl(lease_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let lease = unsafe { File::from_raw_fd(duplicate) };
        let lease_path = directory.join("fixture-owner");
        let independent = private_file(&lease_path)?;
        same_file(&lease, &lease_path)?;
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(anyhow!("fixture owner lease refused"));
        }
        if unsafe { libc::flock(independent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Err(anyhow!("fixture lease was not independently exclusive"));
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock {
            return Err(anyhow!("fixture lease observation failed"));
        }
        // Never LOCK_UN: the inherited descriptor shares the operator's open-file description.
        let z = tokio::time::timeout(
            LIMIT,
            Zfs::with_paths(&parent, &Tools::host(), Path::new("/dev/zvol")),
        )
        .await
        .context("fixture opening unresolved")??;
        let mounts = directory.join("mounts");
        let f = Self {
            z,
            parent,
            guid,
            pool,
            pool_guid,
            vdev_path,
            vdev,
            directory: directory_fd,
            _lease: lease,
            mounts,
            children: Vec::new(),
        };
        f.check().await?;
        if f.get(&f.parent, "type").await? != "filesystem"
            || f.get(&f.parent, "encryption").await? != "off"
            || f.get(&f.parent, "origin").await? != "-"
        {
            return Err(anyhow!("fixture must be a keyless, non-clone filesystem"));
        }
        let names = f
            .command(&["list", "-H", "-r", "-t", "all", "-o", "name", &f.parent])
            .await?;
        if names.lines().collect::<Vec<_>>() != [f.parent.as_str()] {
            return Err(anyhow!("fixture parent is not initially empty"));
        }
        let pool_names = f
            .command(&["list", "-H", "-r", "-t", "all", "-o", "name", &f.pool])
            .await?;
        if pool_names.lines().collect::<Vec<_>>() != [f.pool.as_str(), f.parent.as_str()] {
            return Err(anyhow!("fixture pool contains foreign datasets"));
        }
        // O_EXCL directory creation; failure/ambiguity leaves it for the fixture operator.
        std::fs::create_dir(&f.mounts)?;
        Ok(f)
    }
    async fn get(&self, dataset: &str, property: &str) -> Result<String> {
        tokio::time::timeout(LIMIT, self.z.get_ds(dataset, property))
            .await
            .context("fixture property query unresolved")?
    }
    async fn command(&self, args: &[&str]) -> Result<String> {
        tokio::time::timeout(LIMIT, self.z.run(args))
            .await
            .context("fixture command unresolved")?
    }
    async fn check(&self) -> Result<()> {
        same_file(&self.vdev, &self.vdev_path)?;
        let directory = self.vdev_path.parent().context("fixture directory")?;
        let held = self.directory.metadata()?;
        let named = std::fs::symlink_metadata(directory)?;
        if !named.is_dir()
            || named.uid() != 0
            || named.gid() != 0
            || named.mode() & 0o777 != 0o700
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return Err(anyhow!("fixture directory identity changed"));
        }
        same_file(&self._lease, &directory.join("fixture-owner"))?;
        if self.get(&self.parent, "guid").await?.parse::<u64>()? != self.guid {
            return Err(anyhow!("fixture parent GUID changed"));
        }
        if native(
            &self.z,
            "zpool",
            &["get", "-H", "-p", "-o", "value", "guid", &self.pool],
        )
        .await?
        .trim()
        .parse::<u64>()?
            != self.pool_guid
        {
            return Err(anyhow!("fixture pool GUID changed"));
        }
        if native(
            &self.z,
            "zpool",
            &["get", "-H", "-o", "value", "health", &self.pool],
        )
        .await?
        .trim()
            != "ONLINE"
        {
            return Err(anyhow!("fixture pool is not online"));
        }
        let status = native(&self.z, "zpool", &["status", "-P", &self.pool]).await?;
        let leaves: Vec<&str> = status
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|name| name.starts_with('/'))
            .collect();
        if leaves != [self.vdev_path.to_str().context("fixture path encoding")?] {
            return Err(anyhow!(
                "fixture physical leaf does not match the owned backing file"
            ));
        }
        Ok(())
    }
    async fn child(&mut self, name: &str, mounted: bool) -> Result<String> {
        self.check().await?;
        let dataset = format!("{}/{name}", self.parent);
        let mountpoint = if mounted {
            self.mounts.join(name).display().to_string()
        } else {
            "none".into()
        };
        // Native create refuses an existing name; no idempotent/adoption wrapper.
        self.command(&[
            "create",
            "-o",
            "compression=off",
            "-o",
            if mounted {
                "canmount=on"
            } else {
                "canmount=off"
            },
            "-o",
            &format!("mountpoint={mountpoint}"),
            &dataset,
        ])
        .await?;
        let guid = self.get(&dataset, "guid").await?.parse()?;
        if guid == 0 {
            return Err(anyhow!("created child GUID missing; fixture quarantined"));
        }
        self.children.push((name.into(), guid));
        Ok(name.into())
    }
    async fn mounted(&self, relative: &str, expected: &Path) -> Result<()> {
        self.check().await?;
        let dataset = format!("{}/{relative}", self.parent);
        if self.get(&dataset, "mounted").await? != "yes"
            || self.get(&dataset, "mountpoint").await?
                != expected.to_str().context("fixture mountpoint encoding")?
        {
            return Err(anyhow!(
                "fixture data path is not the expected mounted filesystem"
            ));
        }
        Ok(())
    }
    async fn settled(&self) -> Result<()> {
        tokio::time::timeout(LIMIT, self.z.drain_io())
            .await
            .context("fixture child ownership unresolved")?;
        if self.z.owners.pending() != 0 || self.z.stalled(Duration::ZERO).is_some() {
            return Err(anyhow!("fixture returned before child owner closed"));
        }
        self.check().await
    }
    async fn cleanup(self) -> Result<()> {
        self.settled().await?;
        for (name, guid) in self.children.iter().rev() {
            self.check().await?;
            let dataset = format!("{}/{name}", self.parent);
            if self.get(&dataset, "guid").await?.parse::<u64>()? != *guid {
                return Err(anyhow!("owned child GUID changed; fixture quarantined"));
            }
            let inventory = self
                .command(&["list", "-H", "-r", "-t", "all", "-o", "name", &dataset])
                .await?;
            let allowed = if name == "source" {
                vec![dataset.clone(), format!("{dataset}@roundtrip")]
            } else {
                vec![
                    dataset.clone(),
                    format!("{dataset}/received"),
                    format!("{dataset}/received@roundtrip"),
                ]
            };
            if inventory
                .lines()
                .any(|item| !allowed.iter().any(|name| name == item))
            {
                return Err(anyhow!("unexpected child inventory; fixture quarantined"));
            }
            tokio::time::timeout(LIMIT, self.z.destroy(name))
                .await
                .context("fixture destroy unresolved; operator must retain fixture")??;
        }
        self.settled().await?;
        let names = self
            .command(&["list", "-H", "-r", "-t", "all", "-o", "name", &self.parent])
            .await?;
        if names.lines().collect::<Vec<_>>() != [self.parent.as_str()] {
            return Err(anyhow!("fixture child absence unverified"));
        }
        for name in ["source", "restored"] {
            let path = self.mounts.join(name);
            if path.exists() {
                std::fs::remove_dir(path)?;
            }
        }
        std::fs::remove_dir(&self.mounts)?;
        Ok(())
    }
}

#[test]
fn native_fixture_scope_refuses_root_foreign_or_missing_binding() {
    let mut random = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let encoded = hex::encode(random);
    let nonce = encoded.as_str();
    assert!(scope(&format!("bqown-{nonce}/fixture"), nonce).is_ok());
    for wrong in ["", "byard", "byard/m/m_foreign", "bqown-x/fixture"] {
        assert!(scope(wrong, nonce).is_err());
    }
    assert!(scope("bqown-x/fixture", "").is_err());
}

#[tokio::test]
#[ignore = "requires Linux root and an exact operator-provisioned isolated keyless ZFS fixture; never creates a pool"]
async fn native_owned_stream_roundtrip_and_failure_settlement() -> Result<()> {
    let mut f = Fixture::open().await?;
    let source = f.child("source", true).await?;
    f.mounted(&source, &f.mounts.join("source")).await?;
    let mut payload = vec![0; PAYLOAD];
    rand::rngs::OsRng.fill_bytes(&mut payload);
    let expected = Sha256::digest(&payload);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(f.mounts.join("source/payload"))?;
    file.write_all(&payload)?;
    file.sync_all()?;
    drop(file);
    f.check().await?;
    f.command(&["snapshot", &format!("{}/source@roundtrip", f.parent)])
        .await?;
    let snapshot_guid = f
        .get(&format!("{}/source@roundtrip", f.parent), "guid")
        .await?;
    let stream = tokio::time::timeout(
        LIMIT,
        f.z.send_with(&source, "roundtrip", None, |stdout| async move {
            let mut stream = Vec::new();
            stdout.take(MAX_STREAM + 1).read_to_end(&mut stream).await?;
            if stream.len() as u64 > MAX_STREAM {
                return Err(anyhow!("fixture stream bound exceeded"));
            }
            Ok(stream)
        }),
    )
    .await
    .context("source outcome unresolved; operator must retain fixture")??;
    assert!(
        stream.len() > 2 << 20,
        "noncompressible fixture must exceed pipe capacity"
    );
    f.settled().await?;
    let destination = f.child("success", false).await?;
    let bytes = stream.clone();
    tokio::time::timeout(
        LIMIT,
        f.z.receive_with(
            &format!("{destination}/received"),
            move |mut stdin| async move {
                stdin.write_all(&bytes).await?;
                stdin.shutdown().await?;
                Ok(())
            },
        ),
    )
    .await
    .context("receive outcome unresolved; operator must retain fixture")??;
    f.settled().await?;
    let received = format!("{}/success/received", f.parent);
    if f.get(&received, "guid").await?.parse::<u64>()? == 0
        || f.get(&format!("{received}@roundtrip"), "guid").await? != snapshot_guid
    {
        return Err(anyhow!("received snapshot identity mismatch"));
    }
    f.command(&["set", "canmount=noauto", &received]).await?;
    f.command(&[
        "set",
        &format!("mountpoint={}", f.mounts.join("restored").display()),
        &received,
    ])
    .await?;
    f.command(&["mount", &received]).await?;
    f.mounted("success/received", &f.mounts.join("restored"))
        .await?;
    let mut restored = Vec::new();
    File::open(f.mounts.join("restored/payload"))?
        .take(PAYLOAD as u64 + 1)
        .read_to_end(&mut restored)?;
    assert!(
        restored.len() == PAYLOAD,
        "restored payload length mismatch"
    );
    assert!(
        Sha256::digest(&restored) == expected,
        "restored payload SHA256 mismatch"
    );

    let failed = tokio::time::timeout(
        LIMIT,
        f.z.send_with(&source, "roundtrip", None, |mut stdout| async move {
            let mut part = vec![0; 64 << 10];
            stdout.read_exact(&mut part).await?;
            Err::<(), _>(anyhow!("fixture partial source read failed"))
        }),
    )
    .await
    .context("failed source remains unresolved")?;
    assert!(failed
        .unwrap_err()
        .to_string()
        .contains("fixture partial source read failed"));
    f.settled().await?;
    for (name, partial) in [("failed-get", false), ("failed-copy", true)] {
        let parent = f.child(name, false).await?;
        let bytes = stream.clone();
        let failed = tokio::time::timeout(
            LIMIT,
            f.z.receive_with(&format!("{parent}/received"), move |mut stdin| async move {
                if partial {
                    stdin.write_all(&bytes[..64 << 10]).await?;
                }
                Err::<(), _>(anyhow!("fixture input transfer failed"))
            }),
        )
        .await
        .context("failed receiver remains unresolved")?;
        assert!(failed
            .unwrap_err()
            .to_string()
            .contains("fixture input transfer failed"));
        f.settled().await?;
    }
    f.cleanup().await?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "briqyard.owned-stream-helper.v1",
            "payloadBytes": PAYLOAD,
            "payloadSHA256": hex::encode(expected),
            "streamBytes": stream.len(),
            "streamSHA256": hex::encode(Sha256::digest(&stream)),
            "ownedChildrenRemaining": 0,
            "helperSettlementPassed": true
        })
    );
    Ok(())
}
