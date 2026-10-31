//! The HTTP client: calls, refusals, watches and the lines they read.

use super::*;

pub(super) struct Client {
    pub(super) base: String,
    pub(super) token: Option<String>,
    pub(super) http: reqwest::Client,
}

/// A call's deadline: a create may pull an image for minutes. A watch has none.
pub(super) const CALL_TIMEOUT: Duration = Duration::from_secs(900);
/// A watch with no line this long is gone: the server sends one every 30 s.
pub(super) const WATCH_SILENCE: Duration = Duration::from_secs(90);
/// A host upgrade: the bootstrap script's half hour, then the host's return.
pub(super) const UPGRADE_TIMEOUT: Duration = Duration::from_secs(2400);

impl Client {
    fn file_request(
        &self,
        method: reqwest::Method,
        id: &str,
        path: &str,
    ) -> Result<reqwest::RequestBuilder> {
        api::files::check_path(path).map_err(|e| anyhow!(e))?;
        let mut url = url::Url::parse(&format!("{}/v1/machines/{id}/files/content", self.base))?;
        url.query_pairs_mut().append_pair("path", path);
        let mut request = self
            .http
            .request(method, url)
            .timeout(Duration::from_secs(api::files::TRANSFER_SEC));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }

    async fn file_capabilities(&self, id: &str) -> Result<api::files::FileCapabilities> {
        self.call(
            reqwest::Method::GET,
            &format!("/v1/machines/{id}/files/capabilities"),
            NONE,
        )
        .await
    }

    pub(super) async fn put_file(&self, id: &str, local: &str, path: &str) -> Result<()> {
        let caps = self.file_capabilities(id).await?;
        let file = tokio::fs::File::open(local)
            .await
            .with_context(|| local.to_string())?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            bail!("{local}: need a regular file");
        }
        if !caps.file_stream_v1 {
            if metadata.len() > api::files::LEGACY_MAX_SIZE {
                bail!("init {} supports files only through 1 MiB; an image change installs streaming support", caps.init_version);
            }
            use tokio::io::AsyncReadExt;
            let mut data = Vec::new();
            file.take(api::files::LEGACY_MAX_SIZE + 1)
                .read_to_end(&mut data)
                .await?;
            if data.len() as u64 > api::files::LEGACY_MAX_SIZE {
                bail!("legacy file exceeds 1 MiB; an image change installs streaming support");
            }
            self.raw(
                reqwest::Method::PUT,
                &format!("/v1/machines/{id}/files"),
                Some(&api::PutFileRequest {
                    path: path.into(),
                    base64: api::guest::base64_encode(&data),
                    mode: None,
                }),
            )
            .await?;
            return Ok(());
        }
        api::files::check_size(metadata.len()).map_err(|e| anyhow!(e))?;
        let response = self
            .file_request(reqwest::Method::PUT, id, path)?
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, metadata.len())
            .body(reqwest::Body::wrap_stream(
                tokio_util::io::ReaderStream::with_capacity(file, api::files::CHUNK_SIZE),
            ))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(refusal(response).await);
        }
        Ok(())
    }

    pub(super) async fn get_file(&self, id: &str, path: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let caps = self.file_capabilities(id).await?;
        if !caps.file_stream_v1 {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("path", path);
            let response = self
                .send(
                    reqwest::Method::GET,
                    &format!("/v1/machines/{id}/files?{}", query.finish()),
                    NONE,
                    Some(CALL_TIMEOUT),
                )
                .await?;
            let file: api::FileResponse =
                serde_json::from_slice(&bounded_legacy_json(response).await?)?;
            let data = api::files::legacy_bytes(&file.base64).map_err(|e| anyhow!(e))?;
            let mut stdout = tokio::io::stdout();
            stdout.write_all(&data).await?;
            stdout.flush().await?;
            return Ok(());
        }
        let mut response = self
            .file_request(reqwest::Method::GET, id, path)?
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(refusal(response).await);
        }
        let size = response
            .content_length()
            .ok_or_else(|| anyhow!("file response omitted Content-Length"))?;
        api::files::check_size(size).map_err(|e| anyhow!(e))?;
        let mut stdout = tokio::io::stdout();
        while let Some(chunk) = response.chunk().await? {
            stdout.write_all(&chunk).await?;
        }
        stdout.flush().await?;
        Ok(())
    }

    pub(super) async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<T> {
        let text = self.raw(method, path, body).await?;
        if text.is_empty() {
            return serde_json::from_str("null").map_err(|_| anyhow!("empty response"));
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub(super) async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<String> {
        let resp = self.send(method, path, body, Some(CALL_TIMEOUT)).await?;
        Ok(resp.text().await?)
    }

    /// Sends a request; an answer that is not a success is the error it carries.
    pub(super) async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response> {
        if (method == reqwest::Method::POST && path == "/v1/machines")
            || (method == reqwest::Method::PATCH && path.starts_with("/v1/machines/"))
        {
            if let Some(body) = body {
                if serde_json::to_value(body)?["egress"]["siblings"] == true {
                    let mut check = self
                        .http
                        .get(format!("{}/v1/status", self.base))
                        .timeout(Duration::from_secs(10));
                    if let Some(token) = &self.token {
                        check = check.bearer_auth(token);
                    }
                    let response = check.send().await?;
                    if !response.status().is_success() {
                        return Err(refusal(response).await);
                    }
                    let status: serde_json::Value = response.json().await?;
                    if status["egress_siblings_v1"] != true {
                        bail!("server does not support egress.siblings");
                    }
                }
            }
        }
        let mut req = self.http.request(method, format!("{}{}", self.base, path));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("request {}", self.base))?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(refusal(resp).await)
    }

    /// A machine a create answered `creating` (ADR 0048), once it runs: `/wait` again while
    /// it is on its way; one that ran and stopped (a command that exits at once) as it is
    /// then; a create or a boot that failed is the error.
    pub(super) async fn running(&self, m: api::Machine) -> Result<api::Machine> {
        if m.state != api::state::CREATING {
            return Ok(m);
        }
        let path = format!("/v1/machines/{}/wait?for=running&timeout=600", m.id);
        let mut done: api::Machine = loop {
            match self.call(reqwest::Method::POST, &path, NONE).await {
                Err(e) if refused_with(&e, "not_ready") => continue,
                Err(e) if refused_with(&e, "not_running") => {
                    let path = format!("/v1/machines/{}", m.id);
                    break self.call(reqwest::Method::GET, &path, NONE).await?;
                }
                other => break other?,
            }
        };
        // Through a fleet, the create's answer names the host; a wait's does not.
        if done.host.is_empty() {
            done.host = m.host;
        }
        Ok(done)
    }

    /// Every event of a read, page after page, and the cursor after the last.
    pub(super) async fn events(
        &self,
        path: &str,
        since: Option<String>,
    ) -> Result<(Vec<api::Event>, String)> {
        let (mut all, mut cursor) = (Vec::new(), since.unwrap_or_default());
        loop {
            let page: api::EventsPage = self
                .call(reqwest::Method::GET, &with_since(path, &cursor), NONE)
                .await?;
            let full = page.events.len() == api::events_limit(None);
            all.extend(page.events);
            cursor = page.next;
            if !full {
                return Ok((all, cursor));
            }
        }
    }

    /// A watch: each event as it comes, until the server ends it (with the reason, an error).
    pub(super) async fn watch(&self, path: &str, mut each: impl FnMut(&api::Event)) -> Result<()> {
        self.stream(path, |line| {
            if let Some(e) = watch_line(line)? {
                each(&e);
            }
            Ok(ControlFlow::Continue(()))
        })
        .await
    }

    /// An NDJSON stream (a watch, a logs follow): each line as it comes, until `each` breaks
    /// or fails, or the server ends it.
    pub(super) async fn stream(
        &self,
        path: &str,
        mut each: impl FnMut(&str) -> Result<ControlFlow<()>>,
    ) -> Result<()> {
        let mut resp = self.send(reqwest::Method::GET, path, NONE, None).await?;
        let mut buf = Vec::new();
        loop {
            let chunk = tokio::time::timeout(WATCH_SILENCE, resp.chunk())
                .await
                .map_err(|_| anyhow!("no word from {} in {WATCH_SILENCE:?}", self.base))??;
            let Some(chunk) = chunk else {
                bail!("the stream ended");
            };
            buf.extend_from_slice(&chunk);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                if each(&String::from_utf8_lossy(&line))?.is_break() {
                    return Ok(());
                }
            }
        }
    }
}

/// Bound the encoded response before JSON parsing or base64 allocation.
async fn bounded_legacy_json(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > api::files::LEGACY_MAX_JSON.saturating_sub(data.len()) {
            bail!("legacy file response exceeds 1 MiB; an image change installs streaming support");
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

/// The error an answer that is not a success carries: its `ApiError`, else its status and body.
pub(super) async fn refusal(resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return e.into(),
    };
    match serde_json::from_str::<api::ApiError>(&text) {
        Ok(e) => Refused(e).into(),
        Err(_) => anyhow!("{status}: {}", text.trim()),
    }
}

/// A refusal the API explained: what the caller may read its code from.
#[derive(Debug)]
pub(super) struct Refused(api::ApiError);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = &self.0;
        match e.request_id.is_empty() {
            true => write!(f, "{} ({})", e.error, e.code),
            false => write!(f, "{} ({}, request {})", e.error, e.code, e.request_id),
        }
    }
}

impl std::error::Error for Refused {}

/// Whether `err` is the API's refusal with this code.
pub(super) fn refused_with(err: &anyhow::Error, code: &str) -> bool {
    err.downcast_ref::<Refused>()
        .is_some_and(|r| r.0.code == code)
}

/// A line of a logs follow: a console line, a heartbeat (`{}`: nothing), or the end: a
/// destroyed machine ends it (`Break`), anything else is the error that ends it.
pub(super) fn follow_line(line: &str) -> Result<ControlFlow<String, Option<api::LogLine>>> {
    let v: serde_json::Value =
        serde_json::from_str(line).with_context(|| format!("follow line {:?}", line.trim()))?;
    if v.get("ts").is_some() {
        return Ok(ControlFlow::Continue(Some(serde_json::from_value(v)?)));
    }
    match serde_json::from_value::<api::ApiError>(v) {
        Ok(e) if e.code == "destroyed" => Ok(ControlFlow::Break(e.error)),
        Ok(e) => bail!("{} ({})", e.error, e.code),
        Err(_) => Ok(ControlFlow::Continue(None)),
    }
}

/// `GET /v1/machines` for a namespace or every one, with label selectors.
pub(super) fn machines_path(namespace: Option<&str>, labels: &[String]) -> String {
    let mut u = reqwest::Url::parse("http://briqyard/v1/machines").expect("a URL");
    {
        let mut q = u.query_pairs_mut();
        if let Some(t) = namespace {
            q.append_pair("namespace", t);
        }
        for l in labels {
            q.append_pair("label", l);
        }
    }
    match u.query() {
        Some(q) if !q.is_empty() => format!("/v1/machines?{q}"),
        _ => "/v1/machines".into(),
    }
}

/// A namespace's PUT route, with where a fleet places a namespace that has no host yet.
pub(super) fn namespace_put_path(namespace: &str, what: &str, region: Option<&str>) -> String {
    match region {
        Some(r) => format!("/v1/namespaces/{namespace}/{what}?region={r}"),
        None => format!("/v1/namespaces/{namespace}/{what}"),
    }
}

/// A line of a watch: an event, a heartbeat (`{}`: nothing), or the error that ends it.
pub(super) fn watch_line(line: &str) -> Result<Option<api::Event>> {
    let v: serde_json::Value =
        serde_json::from_str(line).with_context(|| format!("watch line {:?}", line.trim()))?;
    if v.get("seq").is_some() {
        return Ok(Some(serde_json::from_value(v)?));
    }
    if let Ok(e) = serde_json::from_value::<api::ApiError>(v) {
        bail!("{} ({})", e.error, e.code);
    }
    Ok(None)
}

pub(super) fn fingerprint_arg(s: &str) -> Result<String, String> {
    api::tls::parse_fingerprint(s)
}

/// The HTTP client: pinned to a daemon's certificate (https only), or the web PKI's.
pub(super) fn http_client(tls_fingerprint: Option<&str>) -> Result<reqwest::Client> {
    // Each call has its own deadline (`CALL_TIMEOUT`); a watch has none.
    let b = reqwest::Client::builder().connect_timeout(Duration::from_secs(10));
    let b = match tls_fingerprint {
        Some(fp) => b
            .use_preconfigured_tls(api::tls::pinned_client(fp))
            .https_only(true),
        None => b,
    };
    Ok(b.build()?)
}

pub(super) fn print_json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}
