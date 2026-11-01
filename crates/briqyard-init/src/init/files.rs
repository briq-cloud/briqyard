//! Raw single-file streams. Descriptor-relative paths never follow symlinks.

use super::*;
use briqyard_api::files as wire;
use rustix::fs::{self as at, AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
static TRANSFERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Install a boot file with the same descriptor-relative, no-symlink semantics as uploads.
pub(super) async fn install(root: &Path, path: &str, mode: u32, data: &[u8]) -> Result<()> {
    wire::check_path(path).map_err(|e| anyhow!(e))?;
    let mut upload = Upload::new(root, path)?;
    upload.file.write_all(data).await?;
    upload.file.flush().await?;
    upload.file.sync_all().await?;
    upload.commit(Some(file_mode(mode)))?;
    at::fsync(&upload.dir)?;
    Ok(())
}

pub(super) async fn serve<R, W>(mut input: R, output: Arc<tokio::sync::Mutex<W>>, req: Request)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Ok(_permit) = TRANSFERS.try_acquire() else {
        send(&output, &Response::error("too many file transfers")).await;
        return;
    };
    let mut ready = false;
    let result = tokio::time::timeout(Duration::from_secs(wire::TRANSFER_SEC), async {
        wire::check_path(&req.path).map_err(|e| anyhow!(e))?;
        match req.op.as_str() {
            "put_stream" => {
                if let Some(size) = req.size {
                    wire::check_size(size).map_err(|e| anyhow!(e))?;
                }
                if req.file_mode.is_some_and(|mode| mode > 0o777) {
                    return Err(anyhow!("invalid file mode"));
                }
                let mut upload = Upload::new(Path::new("/"), &req.path)?;
                send(&output, &Response::new("ready")).await;
                let mut total = 0u64;
                let mut hash = Sha256::new();
                let mut buf = vec![0; wire::CHUNK_SIZE];
                loop {
                    let length = idle(input.read_u32()).await? as usize;
                    if length == 0 {
                        break;
                    }
                    if length > buf.len() {
                        return Err(anyhow!("file chunk exceeds {} bytes", buf.len()));
                    }
                    let next = wire::streamed_size(total, length as u64, req.size)
                        .map_err(|e| anyhow!(e))?;
                    idle(input.read_exact(&mut buf[..length])).await?;
                    idle(upload.file.write_all(&buf[..length])).await?;
                    hash.update(&buf[..length]);
                    total = next;
                }
                if req.size.is_some_and(|size| size != total) {
                    return Err(anyhow!("file stream shorter than declared size"));
                }
                // Only the zero-length terminal commits; EOF or a failed HTTP body never does.
                idle(upload.file.flush()).await?;
                idle(upload.file.sync_all()).await?;
                upload.commit(req.file_mode)?;
                send(
                    &output,
                    &Response {
                        kind: "ok".into(),
                        size: Some(total),
                        sha256: hex::encode(hash.finalize()),
                        ..Default::default()
                    },
                )
                .await;
            }
            "get_stream" => {
                let file = open_file(Path::new("/"), &req.path)?;
                let size = file.metadata()?.len();
                wire::check_size(size).map_err(|e| anyhow!(e))?;
                let mut file = tokio::fs::File::from_std(file);
                ready = true;
                send(
                    &output,
                    &Response {
                        kind: "ready".into(),
                        size: Some(size),
                        ..Default::default()
                    },
                )
                .await;
                let mut left = size;
                let mut buf = vec![0; wire::CHUNK_SIZE];
                let mut out = output.lock().await;
                while left > 0 {
                    let n = (left as usize).min(buf.len());
                    idle(file.read_exact(&mut buf[..n])).await?;
                    idle(out.write_all(&buf[..n])).await?;
                    left -= n as u64;
                }
                idle(out.flush()).await?;
            }
            _ => unreachable!(),
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    // A failed download closes: no framed error may become part of its raw body.
    if req.op == "put_stream" {
        if let Err(e) = result.unwrap_or_else(|_| Err(anyhow!("file transfer timeout"))) {
            let _ = tokio::time::timeout(
                Duration::from_secs(wire::IDLE_SEC),
                send(&output, &Response::error(e.to_string())),
            )
            .await;
        }
    } else if !ready {
        if let Ok(Err(e)) = result {
            // Once ready, failure is EOF, never an error frame in the raw body.
            let _ = tokio::time::timeout(
                Duration::from_secs(wire::IDLE_SEC),
                send(&output, &Response::error(e.to_string())),
            )
            .await;
        }
    }
}

async fn idle<T>(f: impl std::future::Future<Output = std::io::Result<T>>) -> Result<T> {
    Ok(tokio::time::timeout(Duration::from_secs(wire::IDLE_SEC), f)
        .await
        .context("file stream idle timeout")??)
}

/// Open one directory at a time, with a descriptor pinned across rename races.
fn parent(root: &Path, path: &str, create: bool) -> Result<(OwnedFd, CString)> {
    wire::check_path(path).map_err(|e| anyhow!(e))?;
    let mut dir = at::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut parts = path[1..].split('/').peekable();
    while let Some(part) = parts.next() {
        let name = CString::new(part)?;
        if parts.peek().is_none() {
            return Ok((dir, name));
        }
        if create {
            match at::mkdirat(&dir, &name, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        dir = at::openat(
            &dir,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
    }
    Err(anyhow!("path must name a file"))
}

fn open_file(root: &Path, path: &str) -> Result<fs::File> {
    let (dir, name) = parent(root, path, false)?;
    let fd = at::openat(
        &dir,
        &name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let file = fs::File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(anyhow!("path must name a regular file"));
    }
    Ok(file)
}

struct Upload {
    dir: OwnedFd,
    name: CString,
    temporary: CString,
    file: tokio::fs::File,
    committed: bool,
}

impl Upload {
    fn new(root: &Path, path: &str) -> Result<Self> {
        Self::create(
            root,
            path,
            (0..64).map(|_| NEXT.fetch_add(1, Ordering::Relaxed)),
        )
    }
    fn create(root: &Path, path: &str, sequence: impl IntoIterator<Item = u64>) -> Result<Self> {
        let (dir, name) = parent(root, path, true)?;
        for number in sequence {
            let temporary = CString::new(format!(
                ".briqyard-upload-{}-{}",
                std::process::id(),
                number
            ))?;
            if temporary == name {
                continue;
            }
            match at::openat(
                &dir,
                &temporary,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        dir,
                        name,
                        temporary,
                        file: tokio::fs::File::from_std(fs::File::from(fd)),
                        committed: false,
                    })
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(anyhow!("cannot create upload temporary file"))
    }
    fn commit(&mut self, mode: Option<u32>) -> Result<()> {
        let mode = match mode {
            Some(mode) => mode,
            None => match at::statat(&self.dir, &self.name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat)
                    if at::FileType::from_raw_mode(stat.st_mode) == at::FileType::RegularFile =>
                {
                    stat.st_mode & 0o777
                }
                Ok(_) | Err(rustix::io::Errno::NOENT) => 0o644,
                Err(e) => return Err(e.into()),
            },
        };
        at::fchmod(&self.file, Mode::from_raw_mode(mode))?;
        // rename replaces a final symlink itself; it never writes its target.
        at::renameat(&self.dir, &self.temporary, &self.dir, &self.name)?;
        self.committed = true;
        Ok(())
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        if !self.committed {
            let _ = at::unlinkat(&self.dir, &self.temporary, AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::testutil::state;
    use std::os::unix::fs::symlink;

    async fn read_response<S: AsyncRead + Unpin>(s: &mut S) -> Response {
        let mut hdr = [0; 4];
        s.read_exact(&mut hdr).await.unwrap();
        let mut body = vec![0; u32::from_be_bytes(hdr) as usize];
        s.read_exact(&mut body).await.unwrap();
        guest::decode_frame(&body).unwrap()
    }

    #[tokio::test]
    async fn raw_file_roundtrip_larger_than_a_frame_and_empty() {
        let root = tempfile::tempdir().unwrap();
        for (declared, data) in [
            (true, vec![]),
            (false, vec![]),
            (true, (0..(5 << 20)).map(|n| (n % 251) as u8).collect()),
            (false, (0..(5 << 20)).map(|n| (n % 251) as u8).collect()),
        ] {
            let path = root.path().join("nested/a & b.bin");
            let req = Request {
                op: "put_stream".into(),
                path: path.to_str().unwrap().into(),
                size: declared.then_some(data.len() as u64),
                file_mode: Some(0o640),
                ..Default::default()
            };
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(super::super::serve::handle(state(), server));
            client
                .write_all(&guest::encode_frame(&req).unwrap())
                .await
                .unwrap();
            assert_eq!(read_response(&mut client).await.kind, "ready");
            for chunk in data.chunks(wire::CHUNK_SIZE) {
                client.write_u32(chunk.len() as u32).await.unwrap();
                client.write_all(chunk).await.unwrap();
            }
            client.write_u32(0).await.unwrap();
            let result = read_response(&mut client).await;
            assert_eq!(result.kind, "ok");
            assert_eq!(result.size, Some(data.len() as u64));
            assert_eq!(result.sha256, hex::encode(Sha256::digest(&data)));
            task.await.unwrap();
            assert_eq!(fs::read(&path).unwrap(), data);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(super::super::serve::handle(state(), server));
            client
                .write_all(
                    &guest::encode_frame(&Request {
                        op: "get_stream".into(),
                        path: req.path,
                        ..Default::default()
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            let ready = read_response(&mut client).await;
            assert_eq!(ready.kind, "ready");
            assert_eq!(ready.size, Some(data.len() as u64));
            let mut downloaded = Vec::new();
            client.read_to_end(&mut downloaded).await.unwrap();
            assert_eq!(downloaded, data);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn truncated_or_uncommitted_upload_keeps_destination_and_cleans_up() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file");
        fs::write(&path, b"old").unwrap();
        for (size, data) in [(8, &b"half"[..]), (4, &b"full"[..]), (4, &b"full\0"[..])] {
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(super::super::serve::handle(state(), server));
            client
                .write_all(
                    &guest::encode_frame(&Request {
                        op: "put_stream".into(),
                        path: path.to_str().unwrap().into(),
                        size: Some(size),
                        mode: 0o644,
                        ..Default::default()
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(read_response(&mut client).await.kind, "ready");
            client.write_u32(data.len() as u32).await.unwrap();
            client.write_all(data).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(read_response(&mut client).await.kind, "error");
            task.await.unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"old");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[tokio::test]
    async fn symlink_and_hardlink_targets_are_never_written() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("original"), b"old").unwrap();
        for link in ["symlink", "hardlink"] {
            let path = root.path().join(link);
            if link == "symlink" {
                symlink(root.path().join("original"), &path).unwrap();
            } else {
                fs::hard_link(root.path().join("original"), &path).unwrap();
            }
            let mut upload = Upload::new(root.path(), &format!("/{link}")).unwrap();
            upload.file.write_all(b"new").await.unwrap();
            upload.file.flush().await.unwrap();
            upload.commit(Some(0)).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(fs::read(path).unwrap(), b"new");
            assert_eq!(fs::read(root.path().join("original")).unwrap(), b"old");
        }
        symlink(root.path(), root.path().join("link")).unwrap();
        assert!(Upload::new(root.path(), "/link/escape").is_err());
        assert!(open_file(root.path(), "/link/original").is_err());
        symlink("original", root.path().join("readlink")).unwrap();
        assert!(open_file(root.path(), "/readlink").is_err());
    }

    #[tokio::test]
    async fn directory_rename_cannot_redirect_an_open_upload() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut upload = Upload::new(root.path(), "/dir/file").unwrap();
        fs::rename(root.path().join("dir"), root.path().join("old")).unwrap();
        symlink(outside.path(), root.path().join("dir")).unwrap();
        upload.file.write_all(b"safe").await.unwrap();
        upload.file.flush().await.unwrap();
        upload.commit(Some(0o600)).unwrap();
        assert!(!outside.path().join("file").exists());
        assert_eq!(fs::read(root.path().join("old/file")).unwrap(), b"safe");
    }

    #[test]
    fn reading_special_files_is_refused_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(open_file(root.path(), "/fifo").is_err());
        assert!(open_file(root.path(), "/dir").is_err());
        assert!(Upload::new(root.path(), "/../escape").is_err());
    }

    #[tokio::test]
    async fn invalid_streams_are_refused_before_ready() {
        let root = tempfile::tempdir().unwrap();
        for req in [
            Request {
                op: "put_stream".into(),
                path: "/../escape".into(),
                size: Some(0),
                ..Default::default()
            },
            Request {
                op: "put_stream".into(),
                path: "/file".into(),
                size: Some(wire::MAX_SIZE + 1),
                ..Default::default()
            },
            Request {
                op: "put_stream".into(),
                path: "/file".into(),
                size: Some(0),
                file_mode: Some(0o4755),
                ..Default::default()
            },
            Request {
                op: "get_stream".into(),
                path: root.path().join("missing").to_str().unwrap().into(),
                ..Default::default()
            },
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(super::super::serve::handle(state(), server));
            client
                .write_all(&guest::encode_frame(&req).unwrap())
                .await
                .unwrap();
            assert_eq!(read_response(&mut client).await.kind, "error");
            task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn temporary_name_cannot_be_the_destination_and_commit_ends_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let name = format!(".briqyard-upload-{}-10", std::process::id());
        let mut upload = Upload::create(root.path(), &format!("/{name}"), [10, 11]).unwrap();
        assert!(
            !root.path().join(&name).exists(),
            "destination absent until commit"
        );
        assert_eq!(
            upload.temporary.to_str().unwrap(),
            format!(".briqyard-upload-{}-11", std::process::id())
        );
        upload.file.write_all(b"complete").await.unwrap();
        upload.file.flush().await.unwrap();
        upload.commit(Some(0o600)).unwrap();
        // Another writer may reuse the old temporary pathname after the rename.
        let reused = root.path().join(upload.temporary.to_str().unwrap());
        fs::write(&reused, b"other writer").unwrap();
        drop(upload);
        assert_eq!(fs::read(root.path().join(name)).unwrap(), b"complete");
        assert_eq!(fs::read(reused).unwrap(), b"other writer");
    }
    #[tokio::test]
    async fn chunk_bounds_and_declared_totals_fail_without_committing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file");
        fs::write(&path, b"old").unwrap();
        for (size, bytes) in [
            (None, ((wire::CHUNK_SIZE + 1) as u32).to_be_bytes().to_vec()),
            (Some(2), b"\0\0\0\x04full".to_vec()),
            (Some(8), b"\0\0\0\x04full\0\0\0\0".to_vec()),
            (None, b"\0\0\0\x04ha".to_vec()),
            (None, b"\0\0".to_vec()),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(super::super::serve::handle(state(), server));
            client
                .write_all(
                    &guest::encode_frame(&Request {
                        op: "put_stream".into(),
                        path: path.to_str().unwrap().into(),
                        size,
                        ..Default::default()
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(read_response(&mut client).await.kind, "ready");
            client.write_all(&bytes).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(read_response(&mut client).await.kind, "error");
            task.await.unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"old");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[tokio::test]
    async fn absent_mode_preserves_regular_file_permissions_and_defaults_for_new_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).unwrap();
        for (name, mode) in [("/file", 0o711), ("/new", 0o644)] {
            let mut upload = Upload::new(root.path(), name).unwrap();
            upload.file.write_all(b"replacement").await.unwrap();
            upload.file.flush().await.unwrap();
            upload.commit(None).unwrap();
            let file = root.path().join(&name[1..]);
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }
}
