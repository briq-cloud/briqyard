//! Where backups go, the machines' and the fleet's registry's: an S3 bucket (any provider that speaks the API: Scaleway, OVH, Hetzner,
//! AWS, MinIO) or a directory, for development and for a host that backs up to its own second
//! disk. Streams in and out, so a disk of any size passes without landing on the host's disk.

use anyhow::{anyhow, Context, Result};
use rusty_s3::actions::{CreateMultipartUpload, ListObjectsV2, S3Action};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// One part of a multipart upload; S3 wants at least 5 MB for every part but the last.
const PART: usize = 32 << 20;
const SIGN_FOR: Duration = Duration::from_secs(3600);

// One store per daemon: the size difference between the variants costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum ObjectStore {
    File {
        root: PathBuf,
    },
    S3 {
        bucket: Bucket,
        creds: Credentials,
        prefix: String,
        http: reqwest::Client,
    },
}

pub type Reader = Box<dyn AsyncRead + Unpin + Send>;

impl ObjectStore {
    /// `file:///var/lib/briqyard/backups` or `s3://bucket/prefix`; the S3 form needs the
    /// endpoint, the region and the credentials.
    pub fn open(
        store: &str,
        endpoint: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        if let Some(path) = store.strip_prefix("file://") {
            if path.is_empty() {
                return Err(anyhow!("backup.store: file:// needs a path"));
            }
            std::fs::create_dir_all(path).with_context(|| format!("backup store {path}"))?;
            return Ok(Self::File {
                root: PathBuf::from(path),
            });
        }
        if let Some(rest) = store.strip_prefix("s3://") {
            let (name, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            if name.is_empty() {
                return Err(anyhow!("backup.store: s3:// needs a bucket"));
            }
            if endpoint.is_empty() {
                return Err(anyhow!("backup.endpoint is required for an s3:// store"));
            }
            if access_key.is_empty() || secret_key.is_empty() {
                return Err(anyhow!(
                    "BRIQYARD_S3_ACCESS_KEY and BRIQYARD_S3_SECRET_KEY are required for an s3:// store"
                ));
            }
            let endpoint: url::Url = endpoint.parse().context("backup.endpoint")?;
            let region = if region.is_empty() {
                "us-east-1"
            } else {
                region
            };
            let bucket = Bucket::new(
                endpoint,
                UrlStyle::Path,
                name.to_string(),
                region.to_string(),
            )
            .context("backup bucket")?;
            return Ok(Self::S3 {
                bucket,
                creds: Credentials::new(access_key, secret_key),
                prefix: prefix.trim_matches('/').to_string(),
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(3600))
                    .connect_timeout(Duration::from_secs(20))
                    .build()?,
            });
        }
        Err(anyhow!(
            "backup.store {store:?}: want file:///path or s3://bucket/prefix"
        ))
    }

    pub fn describe(&self) -> String {
        match self {
            Self::File { root } => format!("file://{}", root.display()),
            Self::S3 { bucket, prefix, .. } => format!("s3://{}/{prefix}", bucket.name()),
        }
    }

    fn full_key(&self, key: &str) -> String {
        match self {
            Self::S3 { prefix, .. } if !prefix.is_empty() => format!("{prefix}/{key}"),
            _ => key.to_string(),
        }
    }

    fn file_path(root: &Path, key: &str) -> Result<PathBuf> {
        if key.split('/').any(|p| p == ".." || p.is_empty()) {
            return Err(anyhow!("bad object key {key:?}"));
        }
        Ok(root.join(key))
    }

    /// Writes an object from a stream; returns how many bytes it holds.
    pub async fn put(&self, key: &str, mut reader: impl AsyncRead + Unpin + Send) -> Result<u64> {
        match self {
            Self::File { root } => {
                let path = Self::file_path(root, key)?;
                if let Some(p) = path.parent() {
                    tokio::fs::create_dir_all(p).await?;
                }
                let tmp = path.with_extension("part");
                let mut f = tokio::fs::File::create(&tmp).await?;
                let n = tokio::io::copy(&mut reader, &mut f).await?;
                f.sync_all().await?;
                tokio::fs::rename(&tmp, &path).await?;
                Ok(n)
            }
            Self::S3 {
                bucket,
                creds,
                http,
                ..
            } => {
                let key = self.full_key(key);
                // The first part decides: everything in one piece is a single PUT.
                let mut buf = Vec::with_capacity(PART);
                let eof = read_part(&mut reader, &mut buf).await?;
                if eof {
                    let url = bucket.put_object(Some(creds), &key).sign(SIGN_FOR);
                    let n = buf.len() as u64;
                    let resp = http.put(url).body(buf).send().await.context("s3 put")?;
                    s3_ok(resp, "put").await?;
                    return Ok(n);
                }
                let url = bucket
                    .create_multipart_upload(Some(creds), &key)
                    .sign(SIGN_FOR);
                let resp = http.post(url).send().await.context("s3 create upload")?;
                let text = s3_ok(resp, "create upload").await?;
                let upload = CreateMultipartUpload::parse_response(&text)
                    .context("s3 create upload response")?;
                let upload_id = upload.upload_id().to_string();
                let mut etags = Vec::new();
                let mut total = 0u64;
                let mut part_number: u16 = 1;
                let mut done = false;
                while !done {
                    let url = bucket
                        .upload_part(Some(creds), &key, part_number, &upload_id)
                        .sign(SIGN_FOR);
                    total += buf.len() as u64;
                    let body = std::mem::take(&mut buf);
                    let resp = http
                        .put(url)
                        .body(body)
                        .send()
                        .await
                        .context("s3 upload part")?;
                    let etag = resp
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim_matches('"').to_string());
                    s3_ok(resp, "upload part").await?;
                    etags.push(etag.ok_or_else(|| anyhow!("s3 upload part: no etag"))?);
                    part_number += 1;
                    buf = Vec::with_capacity(PART);
                    done = read_part(&mut reader, &mut buf).await?;
                    if done && buf.is_empty() {
                        break;
                    }
                    if done {
                        // The last part, whatever its size.
                        let url = bucket
                            .upload_part(Some(creds), &key, part_number, &upload_id)
                            .sign(SIGN_FOR);
                        total += buf.len() as u64;
                        let body = std::mem::take(&mut buf);
                        let resp = http
                            .put(url)
                            .body(body)
                            .send()
                            .await
                            .context("s3 upload part")?;
                        let etag = resp
                            .headers()
                            .get("etag")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.trim_matches('"').to_string());
                        s3_ok(resp, "upload part").await?;
                        etags.push(etag.ok_or_else(|| anyhow!("s3 upload part: no etag"))?);
                    }
                }
                let action = bucket.complete_multipart_upload(
                    Some(creds),
                    &key,
                    &upload_id,
                    etags.iter().map(String::as_str),
                );
                let url = action.sign(SIGN_FOR);
                let body = action.body();
                let resp = http
                    .post(url)
                    .body(body)
                    .send()
                    .await
                    .context("s3 complete upload")?;
                s3_ok(resp, "complete upload").await?;
                Ok(total)
            }
        }
    }

    /// Reads an object as a stream.
    pub async fn get(&self, key: &str) -> Result<Reader> {
        match self {
            Self::File { root } => {
                let f = tokio::fs::File::open(Self::file_path(root, key)?)
                    .await
                    .with_context(|| format!("backup object {key}"))?;
                Ok(Box::new(f))
            }
            Self::S3 {
                bucket,
                creds,
                http,
                ..
            } => {
                let url = bucket
                    .get_object(Some(creds), &self.full_key(key))
                    .sign(SIGN_FOR);
                let resp = http.get(url).send().await.context("s3 get")?;
                if !resp.status().is_success() {
                    return Err(anyhow!(
                        "s3 get {key}: {} {}",
                        resp.status(),
                        resp.text()
                            .await
                            .unwrap_or_default()
                            .chars()
                            .take(200)
                            .collect::<String>()
                    ));
                }
                let stream = resp
                    .bytes_stream()
                    .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())));
                Ok(Box::new(tokio_util::io::StreamReader::new(stream)))
            }
        }
    }

    pub async fn put_bytes(&self, key: &str, data: &[u8]) -> Result<()> {
        self.put(key, std::io::Cursor::new(data.to_vec())).await?;
        Ok(())
    }

    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        let mut r = self.get(key).await?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).await?;
        Ok(out)
    }

    /// Keys under a prefix, sorted.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        match self {
            Self::File { root } => {
                let dir = Self::file_path(root, prefix.trim_end_matches('/'))?;
                let mut out = Vec::new();
                let mut stack = vec![dir.clone()];
                while let Some(d) = stack.pop() {
                    let mut rd = match tokio::fs::read_dir(&d).await {
                        Ok(rd) => rd,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e.into()),
                    };
                    while let Some(e) = rd.next_entry().await? {
                        let p = e.path();
                        if p.is_dir() {
                            stack.push(p);
                        } else if p.extension().map(|x| x != "part").unwrap_or(true) {
                            let rel = p.strip_prefix(root).unwrap_or(&p);
                            out.push(rel.to_string_lossy().replace('\\', "/"));
                        }
                    }
                }
                out.sort();
                Ok(out)
            }
            Self::S3 {
                bucket,
                creds,
                http,
                prefix: base,
            } => {
                let full = if base.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{base}/{prefix}")
                };
                let mut out = Vec::new();
                let mut token: Option<String> = None;
                loop {
                    let mut action = bucket.list_objects_v2(Some(creds));
                    action.with_prefix(&full);
                    if let Some(t) = &token {
                        action.with_continuation_token(t);
                    }
                    let url = action.sign(SIGN_FOR);
                    let resp = http.get(url).send().await.context("s3 list")?;
                    let text = s3_ok(resp, "list").await?;
                    let page = ListObjectsV2::parse_response(&text).context("s3 list response")?;
                    for c in page.contents {
                        let k = c
                            .key
                            .strip_prefix(&format!("{base}/"))
                            .unwrap_or(&c.key)
                            .to_string();
                        out.push(k);
                    }
                    match page.next_continuation_token {
                        Some(t) => token = Some(t),
                        None => break,
                    }
                }
                out.sort();
                Ok(out)
            }
        }
    }

    /// Removes an object; missing is success. For the pruning of old backups.
    #[allow(dead_code)]
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self {
            Self::File { root } => {
                match tokio::fs::remove_file(Self::file_path(root, key)?).await {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
            Self::S3 {
                bucket,
                creds,
                http,
                ..
            } => {
                let url = bucket
                    .delete_object(Some(creds), &self.full_key(key))
                    .sign(SIGN_FOR);
                let resp = http.delete(url).send().await.context("s3 delete")?;
                s3_ok(resp, "delete").await?;
                Ok(())
            }
        }
    }
}

use futures::StreamExt;

/// Fills `buf` up to a part; true when the stream ended.
async fn read_part(reader: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>) -> Result<bool> {
    let mut chunk = vec![0u8; 1 << 20];
    while buf.len() < PART {
        let want = (PART - buf.len()).min(chunk.len());
        let n = reader.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Ok(true);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(false)
}

async fn s3_ok(resp: reqwest::Response, op: &str) -> Result<String> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!(
            "s3 {op}: {status} {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    Ok(text)
}

/// A writer side for callers that produce bytes (used by tests and the record files).
#[allow(dead_code)]
pub async fn write_all(mut w: impl tokio::io::AsyncWrite + Unpin, data: &[u8]) -> Result<()> {
    w.write_all(data).await?;
    w.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ObjectStore::open(&format!("file://{}", dir.path().display()), "", "", "", "").unwrap();
        assert!(store.describe().starts_with("file://"));
        let data = vec![7u8; 3 << 20];
        let n = store
            .put(
                "backups/m_1/root/a.full",
                std::io::Cursor::new(data.clone()),
            )
            .await
            .unwrap();
        assert_eq!(n, data.len() as u64);
        store.put_bytes("backups/m_1/a.json", b"{}").await.unwrap();
        assert_eq!(
            store.get_bytes("backups/m_1/root/a.full").await.unwrap(),
            data
        );
        assert_eq!(
            store.list("backups/m_1").await.unwrap(),
            vec![
                "backups/m_1/a.json".to_string(),
                "backups/m_1/root/a.full".to_string()
            ]
        );
        assert!(store.list("backups/none").await.unwrap().is_empty());
        store.delete("backups/m_1/root/a.full").await.unwrap();
        store.delete("backups/m_1/root/a.full").await.unwrap();
        assert!(store.get("backups/m_1/root/a.full").await.is_err());
        // No escaping the root.
        assert!(store.get("../etc/passwd").await.is_err());
    }

    #[test]
    fn store_urls() {
        assert!(ObjectStore::open("s3://", "", "", "", "").is_err());
        assert!(
            ObjectStore::open("s3://b/p", "", "", "k", "s").is_err(),
            "no endpoint"
        );
        assert!(ObjectStore::open("s3://b/p", "https://s3.example", "", "", "").is_err());
        let s = ObjectStore::open(
            "s3://b/some/prefix/",
            "https://s3.example",
            "fr-par",
            "k",
            "s",
        )
        .unwrap();
        assert_eq!(s.describe(), "s3://b/some/prefix");
        assert_eq!(s.full_key("x/y"), "some/prefix/x/y");
        assert!(ObjectStore::open("ftp://x", "", "", "", "").is_err());
        assert!(ObjectStore::open("file://", "", "", "", "").is_err());
    }

    #[tokio::test]
    async fn parts_are_read_whole() {
        let data = vec![1u8; PART + 10];
        let mut r = std::io::Cursor::new(data);
        let mut buf = Vec::new();
        assert!(!read_part(&mut r, &mut buf).await.unwrap());
        assert_eq!(buf.len(), PART);
        let mut rest = Vec::new();
        assert!(read_part(&mut r, &mut rest).await.unwrap());
        assert_eq!(rest.len(), 10);
    }
}
