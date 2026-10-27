//! Where backups go, the machines' and the fleet's registry's: an S3 bucket (any provider that
//! speaks the API: Scaleway, OVH, Hetzner, AWS, MinIO) or a directory, for development and for a
//! host that backs up to its own second disk. Both are Apache Arrow's `object_store` (ADR 0034):
//! its S3 client (SigV4, multipart upload, retries with backoff, a get that resumes) and its
//! local file system, behind one small API. Streams in and out, so a disk of any size passes
//! without landing on the host's disk or in its memory.

use anyhow::{anyhow, Context, Result};
use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::buffered::BufWriter;
use object_store::client::{
    HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest, HttpResponse,
    HttpResponseBody, HttpService,
};
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::prefix::PrefixStore;
use object_store::{ClientOptions, ObjectStoreExt, RetryConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// One part of a multipart upload (S3 wants at least 5 MB for every part but the last; 10,000
/// parts at most, so 320 GB an object). A stream shorter than a part is a single PUT.
const PART: usize = 32 << 20;
/// Parts in flight at once: a stream holds at most `PART × (UPLOADS + 1)` in memory, 160 MB.
const UPLOADS: usize = 4;
/// A request is given this long to send its body and get its answer's head, then this long
/// between two pieces of its answer: a stalled connection fails, a long download does not.
const STALL: Duration = Duration::from_secs(300);
/// What a failed request gets: tried again with backoff (100 ms doubling to 15 s) up to 10
/// times, within 10 minutes of its first try. A get cut mid-stream resumes where it was.
fn retry() -> RetryConfig {
    RetryConfig {
        max_retries: 10,
        retry_timeout: Duration::from_secs(600),
        ..Default::default()
    }
}

pub struct ObjectStore {
    inner: Arc<dyn object_store::ObjectStore>,
    /// `s3` or `file`, for errors.
    scheme: &'static str,
    url: String,
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
        Self::open_with(store, endpoint, region, access_key, secret_key, retry())
    }

    fn open_with(
        store: &str,
        endpoint: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        retry: RetryConfig,
    ) -> Result<Self> {
        if let Some(path) = store.strip_prefix("file://") {
            if path.is_empty() {
                return Err(anyhow!("backup.store: file:// needs a path"));
            }
            std::fs::create_dir_all(path).with_context(|| format!("backup store {path}"))?;
            let fs = LocalFileSystem::new_with_prefix(path)
                .with_context(|| format!("backup store {path}"))?;
            return Ok(Self {
                inner: Arc::new(fs),
                scheme: "file",
                url: format!("file://{path}"),
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
            let region = if region.is_empty() {
                "us-east-1"
            } else {
                region
            };
            let s3 = AmazonS3Builder::new()
                .with_endpoint(endpoint)
                .with_allow_http(endpoint.starts_with("http://"))
                .with_bucket_name(name)
                .with_region(region)
                .with_access_key_id(access_key)
                .with_secret_access_key(secret_key)
                .with_retry(retry)
                .with_http_connector(Connector)
                .build()
                .map_err(|e| anyhow!("backup bucket: {e}"))?;
            let prefix = prefix.trim_matches('/');
            let inner: Arc<dyn object_store::ObjectStore> = if prefix.is_empty() {
                Arc::new(s3)
            } else {
                let p = Path::parse(prefix).map_err(|e| anyhow!("backup.store prefix: {e}"))?;
                Arc::new(PrefixStore::new(s3, p))
            };
            return Ok(Self {
                inner,
                scheme: "s3",
                url: format!("s3://{name}/{prefix}"),
            });
        }
        Err(anyhow!(
            "backup.store {store:?}: want file:///path or s3://bucket/prefix"
        ))
    }

    pub fn describe(&self) -> String {
        self.url.clone()
    }

    /// A key as a path: `/`-separated, no empty part, no `..`, so a key never leaves the store.
    fn path(key: &str) -> Result<Path> {
        if key.split('/').any(|p| p == ".." || p.is_empty()) {
            return Err(anyhow!("bad object key {key:?}"));
        }
        Path::parse(key).map_err(|e| anyhow!("bad object key {key:?}: {e}"))
    }

    fn failed(&self, op: &str, key: &str, e: impl std::fmt::Display) -> anyhow::Error {
        anyhow!("{} {op} {key}: {e}", self.scheme)
    }

    /// Writes an object from a stream; returns how many bytes it holds. A stream that fails
    /// midway leaves nothing: its upload is aborted.
    pub async fn put(&self, key: &str, reader: impl AsyncRead + Unpin + Send) -> Result<u64> {
        let mut w = BufWriter::with_capacity(self.inner.clone(), Self::path(key)?, PART)
            .with_max_concurrency(UPLOADS);
        let mut reader = tokio::io::BufReader::with_capacity(1 << 20, reader);
        let n = match tokio::io::copy_buf(&mut reader, &mut w).await {
            Ok(n) => n,
            Err(e) => {
                if let Err(err) = w.abort().await {
                    let err = self.failed("abort", key, err);
                    tracing::warn!(key, err = %err, "upload left in the store");
                }
                return Err(self.failed("put", key, e));
            }
        };
        w.shutdown().await.map_err(|e| self.failed("put", key, e))?;
        Ok(n)
    }

    /// Reads an object as a stream.
    pub async fn get(&self, key: &str) -> Result<Reader> {
        let got = self
            .inner
            .get(&Self::path(key)?)
            .await
            .map_err(|e| self.failed("get", key, e))?;
        let (scheme, key) = (self.scheme, key.to_string());
        let stream = got
            .into_stream()
            .map_err(move |e| std::io::Error::other(format!("{scheme} get {key}: {e}")));
        Ok(Box::new(tokio_util::io::StreamReader::new(stream)))
    }

    pub async fn put_bytes(&self, key: &str, data: &[u8]) -> Result<()> {
        self.put(key, data).await?;
        Ok(())
    }

    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        let mut r = self.get(key).await?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).await?;
        Ok(out)
    }

    /// Keys under a prefix, sorted. A prefix is whole path segments: `m_1` is not `m_10`.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let p = Self::path(prefix.trim_end_matches('/'))?;
        let mut out: Vec<String> = self
            .inner
            .list(Some(&p))
            .map_ok(|m| m.location.to_string())
            .try_collect()
            .await
            .map_err(|e| self.failed("list", prefix, e))?;
        out.sort();
        Ok(out)
    }

    /// Removes an object; missing is success. For the pruning of old backups.
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self.inner.delete(&Self::path(key)?).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(self.failed("delete", key, e)),
        }
    }
}

/// The HTTP client under the S3 store: our reqwest (the one the daemon and the fleet use, on
/// ring's TLS) rather than the one `object_store` brings, and the one place that decides what
/// an error may say. `object_store` signs in the `Authorization` header, so its errors name the
/// object's URL and no credential; what it would add from the wire is cut here: a connection
/// error goes without its URL, and an error answer's body becomes its S3 error code alone (an
/// S3 error body can echo the access key id and the request's signature).
#[derive(Debug)]
struct Connector;

impl HttpConnector for Connector {
    fn connect(&self, _: &ClientOptions) -> object_store::Result<HttpClient> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(STALL)
            .build()
            .map_err(|e| object_store::Error::Generic {
                store: "S3",
                source: Box::new(e.without_url()),
            })?;
        Ok(HttpClient::new(Http(client)))
    }
}

#[derive(Debug)]
struct Http(reqwest::Client);

#[async_trait::async_trait]
impl HttpService for Http {
    async fn call(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        use http_body_util::BodyExt;
        let (head, body) = req.into_parts();
        let url = head
            .uri
            .to_string()
            .parse()
            .map_err(|e| HttpError::new(HttpErrorKind::Unknown, e))?;
        let mut r = reqwest::Request::new(head.method, url);
        *r.headers_mut() = head.headers;
        *r.body_mut() = Some(reqwest::Body::wrap(body));
        let resp: http::Response<reqwest::Body> =
            self.0.execute(r).await.map_err(transport)?.into();
        let (head, body) = resp.into_parts();
        if head.status.is_success() || head.status.is_redirection() {
            let body = HttpResponseBody::new(body.map_err(transport));
            return Ok(HttpResponse::from_parts(head, body));
        }
        // An error answer is small; its code is all that is kept.
        let text = http_body_util::Limited::new(body, 64 << 10)
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let code = s3_code(&String::from_utf8_lossy(&text)).unwrap_or_default();
        let body = http_body_util::Full::new(bytes::Bytes::from(code))
            .map_err(|never: std::convert::Infallible| match never {});
        Ok(HttpResponse::from_parts(head, HttpResponseBody::new(body)))
    }
}

/// A reqwest error as `object_store` reads it, without the request's URL. The kind decides the
/// retry: a connection that never opened is tried again; a timeout or a cut connection only
/// when the request is idempotent (a part, a get, a list), never a multipart completion.
fn transport(e: reqwest::Error) -> HttpError {
    let kind = if e.is_timeout() {
        HttpErrorKind::Timeout
    } else if e.is_connect() {
        HttpErrorKind::Connect
    } else if e.is_decode() {
        HttpErrorKind::Decode
    } else {
        HttpErrorKind::Interrupted
    };
    HttpError::new(kind, e.without_url())
}

/// The `<Code>` of an S3 error body: `AccessDenied`, `NoSuchBucket`, `SignatureDoesNotMatch`.
fn s3_code(body: &str) -> Option<String> {
    let start = body.find("<Code>")? + "<Code>".len();
    let len = body[start..].find("</Code>")?;
    let code = &body[start..start + len];
    (!code.is_empty() && code.len() <= 64 && code.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(endpoint: &str) -> ObjectStore {
        let once = RetryConfig {
            max_retries: 0,
            ..Default::default()
        };
        ObjectStore::open_with(
            "s3://bucket/prefix",
            endpoint,
            "",
            "AKIDSECRETID",
            "secret-key",
            once,
        )
        .unwrap()
    }

    async fn every_call_fails(store: &ObjectStore) -> Vec<String> {
        let errs = [
            store.put_bytes("a", b"x").await.unwrap_err(),
            store
                .put("b", std::io::Cursor::new(vec![0u8; PART + 1]))
                .await
                .unwrap_err(),
            store.get_bytes("a").await.unwrap_err(),
            store.list("a").await.unwrap_err(),
            store.delete("a").await.unwrap_err(),
        ];
        errs.iter().map(|e| format!("{e:#} {e:?}")).collect()
    }

    fn no_credential(msg: &str) {
        assert!(msg.contains("s3 "), "{msg}");
        for leak in ["AKIDSECRETID", "secret-key", "Signature", "X-Amz-"] {
            assert!(!msg.contains(leak), "{leak} in {msg}");
        }
    }

    /// A request that cannot connect says what failed, never a credential.
    #[tokio::test]
    async fn a_failed_connection_never_shows_a_credential() {
        // Nothing listens on port 1: every request fails to connect.
        for msg in every_call_fails(&s3("http://127.0.0.1:1")).await {
            no_credential(&msg);
        }
    }

    /// An error answer keeps its status and S3 code; the rest of its body, where a provider
    /// echoes the access key id and the signature, is never in the error.
    #[tokio::test]
    async fn an_error_answer_says_its_code_and_never_its_body() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            let body = "<Error><Code>InvalidAccessKeyId</Code><AWSAccessKeyId>AKIDSECRETID\
                        </AWSAccessKeyId><SignatureProvided>c0ffee</SignatureProvided></Error>";
            let answer = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                let answer = answer.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1 << 16];
                    let _ = c.read(&mut buf).await;
                    let _ = c.write_all(answer.as_bytes()).await;
                });
            }
        });
        for msg in every_call_fails(&s3(&endpoint)).await {
            no_credential(&msg);
            assert!(msg.contains("403"), "{msg}");
            assert!(!msg.contains("c0ffee"), "{msg}");
        }
        let msg = format!("{:#}", s3(&endpoint).get_bytes("a").await.unwrap_err());
        assert!(msg.contains("InvalidAccessKeyId"), "{msg}");
    }

    #[test]
    fn s3_codes() {
        assert_eq!(
            s3_code("<Error><Code>NoSuchKey</Code><Key>a</Key></Error>").as_deref(),
            Some("NoSuchKey")
        );
        assert_eq!(s3_code("<Code>a b</Code>"), None);
        assert_eq!(s3_code("not xml"), None);
    }

    #[tokio::test]
    async fn file_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ObjectStore::open(&format!("file://{}", dir.path().display()), "", "", "", "").unwrap();
        assert!(store.describe().starts_with("file://"));
        // Over a part: a multipart upload, its parts put together on the disk.
        let data: Vec<u8> = (0..PART + (3 << 20)).map(|i| (i % 251) as u8).collect();
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
        assert_eq!(store.get_bytes("backups/m_1/a.json").await.unwrap(), b"{}");
        assert_eq!(
            store.list("backups/m_1/").await.unwrap(),
            vec![
                "backups/m_1/a.json".to_string(),
                "backups/m_1/root/a.full".to_string()
            ]
        );
        store.put_bytes("backups/m_10/b.json", b"{}").await.unwrap();
        assert_eq!(store.list("backups/m_1").await.unwrap().len(), 2);
        assert!(store.list("backups/none").await.unwrap().is_empty());
        store.delete("backups/m_1/root/a.full").await.unwrap();
        store.delete("backups/m_1/root/a.full").await.unwrap();
        assert!(store.get("backups/m_1/root/a.full").await.is_err());
        // No escaping the root.
        assert!(store.get("../etc/passwd").await.is_err());
        assert!(store.put_bytes("a//b", b"").await.is_err());
    }

    /// A stream that fails midway leaves no object and nothing a list shows.
    #[tokio::test]
    async fn a_failed_stream_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ObjectStore::open(&format!("file://{}", dir.path().display()), "", "", "", "").unwrap();
        let died = futures::stream::iter([Err::<bytes::Bytes, _>(std::io::Error::other(
            "zfs send died",
        ))]);
        let broken = std::io::Cursor::new(vec![1u8; 2 * PART + 10])
            .chain(tokio_util::io::StreamReader::new(died));
        let err = store
            .put("backups/m_1/root/x.zfs", broken)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("zfs send died"), "{err:#}");
        assert!(store.list("backups").await.unwrap().is_empty());
        assert!(store.get("backups/m_1/root/x.zfs").await.is_err());
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
        assert!(ObjectStore::open("ftp://x", "", "", "", "").is_err());
        assert!(ObjectStore::open("file://", "", "", "", "").is_err());
    }

    /// Against a real bucket: MinIO in development, Scaleway before a release.
    /// `BRIQYARD_S3_TEST_STORE=s3://bucket/prefix BRIQYARD_S3_TEST_ENDPOINT=… BRIQYARD_S3_TEST_REGION=…
    /// BRIQYARD_S3_ACCESS_KEY=… BRIQYARD_S3_SECRET_KEY=… cargo test -p briqyard-objstore -- --ignored`
    #[tokio::test]
    #[ignore = "needs a bucket"]
    async fn real_bucket_round_trip() {
        let env = |k: &str| std::env::var(k).unwrap_or_default();
        let store = ObjectStore::open(
            &env("BRIQYARD_S3_TEST_STORE"),
            &env("BRIQYARD_S3_TEST_ENDPOINT"),
            &env("BRIQYARD_S3_TEST_REGION"),
            &env("BRIQYARD_S3_ACCESS_KEY"),
            &env("BRIQYARD_S3_SECRET_KEY"),
        )
        .unwrap();
        let run = format!("test/{}", std::process::id());
        // Two parts and a few bytes: a multipart upload with a short last part.
        let data: Vec<u8> = (0..2 * PART + 5).map(|i| (i % 253) as u8).collect();
        let key = format!("{run}/big.zfs");
        let started = std::time::Instant::now();
        let n = store
            .put(&key, std::io::Cursor::new(data.clone()))
            .await
            .unwrap();
        eprintln!("put {n} bytes in {:?}", started.elapsed());
        assert_eq!(n, data.len() as u64);
        store
            .put_bytes(&format!("{run}/a.json"), b"{}")
            .await
            .unwrap();
        assert_eq!(store.get_bytes(&key).await.unwrap(), data);
        assert_eq!(
            store.list(&run).await.unwrap(),
            vec![format!("{run}/a.json"), key.clone()]
        );
        let missing = store.get_bytes(&format!("{run}/none")).await.unwrap_err();
        eprintln!("a missing object: {missing:#}");
        for k in store.list(&run).await.unwrap() {
            store.delete(&k).await.unwrap();
        }
        store.delete(&key).await.unwrap();
        assert!(store.list(&run).await.unwrap().is_empty());
    }
}
