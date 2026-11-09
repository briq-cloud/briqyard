//! The trusted execution channel has its own credentials and transport policy.
//! It never uses the ordinary host administrator forwarding path.

use crate::{api, registry::HostRec};
use reqwest::{header, Client, Method, Url};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

const MAX_BODY: usize = api::execution::MAX_BODY_BYTES;

#[derive(Clone, Copy)]
pub(super) enum Route {
    Instance,
    Register,
    Discover,
    Ownership,
    Protect,
    Delegation,
    Invalidate,
    Revoke,
    Prepare,
    Dispatch,
    Status,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Register => "register",
            Self::Discover => "discover",
            Self::Ownership => "ownership",
            Self::Protect => "protect",
            Self::Delegation => "delegation",
            Self::Invalidate => "invalidate",
            Self::Revoke => "revoke",
            Self::Prepare => "prepare",
            Self::Dispatch => "dispatch",
            Self::Status => "status",
        }
    }

    fn response_limit(self) -> usize {
        match self {
            Self::Dispatch => api::execution::MAX_EXEC_RESPONSE_BYTES,
            _ => MAX_BODY,
        }
    }

    fn installer(self) -> bool {
        !matches!(self, Self::Prepare | Self::Dispatch | Self::Status)
    }
}

/// Errors deliberately contain neither destination URLs nor request/response text.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Configuration,
    Request,
    /// No conclusion about execution is possible. Never resend or change host.
    Unconfirmed,
}

/// Independently trusted destination identity, separate from any routing request.
pub(super) struct TrustedHost<'a> {
    pub id: &'a str,
    pub tls_fingerprint: &'a str,
    pub administrator: &'a str,
}
impl<'a> From<&'a HostRec> for TrustedHost<'a> {
    fn from(host: &'a HostRec) -> Self {
        Self {
            id: &host.id,
            tls_fingerprint: &host.tls_fingerprint,
            administrator: &host.token,
        }
    }
}

pub(super) struct HostTransport {
    client: Client,
    origin: Url,
    installer: header::HeaderValue,
    execution: header::HeaderValue,
    administrator: String,
    host_id: String,
}

impl HostTransport {
    /// Inputs come from locally provisioned credentials and the trusted registry.
    /// This captures one destination; no request can choose a host or supply headers.
    pub(super) fn new(
        host: &HostRec,
        installer: &str,
        execution: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Self::with_endpoint(host, &host.url, installer, execution, timeout)
    }
    pub(super) fn with_endpoint(
        host: &HostRec,
        endpoint: &str,
        installer: &str,
        execution: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Self::from_trusted(
            TrustedHost::from(host),
            endpoint,
            installer,
            execution,
            timeout,
        )
    }
    pub(super) fn from_trusted(
        host: TrustedHost<'_>,
        endpoint: &str,
        installer: &str,
        execution: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if host.id.is_empty()
            || installer.is_empty()
            || execution.is_empty()
            || installer == execution
            || installer == host.administrator
            || execution == host.administrator
            || timeout.is_zero()
            || timeout > Duration::from_secs(300)
        {
            return Err(Error::Configuration);
        }
        let origin = Url::parse(endpoint).map_err(|_| Error::Configuration)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(Error::Configuration);
        }
        let pin =
            api::tls::parse_fingerprint(host.tls_fingerprint).map_err(|_| Error::Configuration)?;
        let bearer = |token: &str| {
            if token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || !b.is_ascii_graphic())
            {
                return Err(Error::Configuration);
            }
            let mut value = header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Configuration)?;
            value.set_sensitive(true);
            Ok(value)
        };
        let client = Client::builder()
            .use_preconfigured_tls(api::tls::pinned_client(&pin))
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            origin,
            installer: bearer(installer)?,
            execution: bearer(execution)?,
            administrator: host.administrator.into(),
            host_id: host.id.into(),
        })
    }

    pub(super) fn administrator_token(&self) -> &str {
        &self.administrator
    }

    pub(super) fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Sends exactly once. The caller must validate the typed ACK against its
    /// durable intent before committing readiness. Failures only permit status recovery.
    pub(super) async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        route: Route,
        input: &T,
    ) -> Result<R, Error> {
        let mut url = self.origin.clone();
        url.set_path(&format!("/internal/execution/v1/{}", route.path()));
        let method = if matches!(route, Route::Instance) {
            Method::GET
        } else {
            Method::POST
        };
        let mut request = self.client.request(method, url).header(
            header::AUTHORIZATION,
            if route.installer() {
                &self.installer
            } else {
                &self.execution
            },
        );
        if !matches!(route, Route::Instance) {
            let body = serde_json::to_vec(input).map_err(|_| Error::Request)?;
            if body.len() > MAX_BODY {
                return Err(Error::Request);
            }
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response_limit = route.response_limit();
        let mut response = request.send().await.map_err(|_| Error::Unconfirmed)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|len| len > response_limit as u64)
        {
            return Err(Error::Unconfirmed);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unconfirmed)? {
            if chunk.len() > response_limit - body.len() {
                return Err(Error::Unconfirmed);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::Unconfirmed)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode, Uri},
        response::IntoResponse,
        Router,
    };
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<(String, String)>>>;

    pub(crate) struct Server {
        pub(crate) host: HostRec,
        pub(crate) calls: Calls,
        pub(crate) instance: Arc<Mutex<String>>,
        handle: axum_server::Handle,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.handle.shutdown();
            self.task.abort();
        }
    }

    async fn endpoint(
        State((calls, instance)): State<(Calls, Arc<Mutex<String>>)>,
        uri: Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        calls.lock().unwrap().push((
            uri.path().into(),
            headers[header::AUTHORIZATION].to_str().unwrap().into(),
        ));
        match uri.path() {
            "/internal/execution/v1/instance" => axum::Json(api::execution::channel::Instance {
                host_instance: instance.lock().unwrap().clone(),
            })
            .into_response(),
            "/internal/execution/v1/protect" => (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "/unexpected")],
                "{}",
            )
                .into_response(),
            "/internal/execution/v1/dispatch" => {
                let requested: serde_json::Value = serde_json::from_slice(&body).unwrap();
                match requested.as_str() {
                    Some("capture_control_bytes") => axum::Json(api::ExecResult {
                        stdout: "\0".repeat(api::execution::MAX_CAPTURE_BYTES as usize),
                        stderr: "\0".repeat(api::execution::MAX_CAPTURE_BYTES as usize),
                        exit_code: 0,
                        timed_out: false,
                    })
                    .into_response(),
                    Some("oversized") => {
                        axum::Json("x".repeat(api::execution::MAX_EXEC_RESPONSE_BYTES))
                            .into_response()
                    }
                    _ => (StatusCode::SERVICE_UNAVAILABLE, "{}").into_response(),
                }
            }
            "/internal/execution/v1/status" => " ".repeat(MAX_BODY + 1).into_response(),
            "/internal/execution/v1/register" => axum::Json(api::ExecResult {
                stdout: serde_json::from_slice::<api::ExecRequest>(&body)
                    .unwrap()
                    .stdin,
                stderr: String::new(),
                exit_code: 0,
                timed_out: false,
            })
            .into_response(),
            _ => "{}".into_response(),
        }
    }

    pub(crate) fn server() -> Server {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let config = api::tls::server_config(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut host = host(&format!("https://{}", listener.local_addr().unwrap()));
        host.tls_fingerprint = api::tls::fingerprint(cert.cert.der());
        let calls = Calls::default();
        let instance = Arc::new(Mutex::new("host-instance".to_owned()));
        let router = Router::new()
            .fallback(endpoint)
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
            .with_state((calls.clone(), instance.clone()));
        let handle = axum_server::Handle::new();
        let running = handle.clone();
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(
                listener,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            )
            .handle(running)
            .serve(router.into_make_service())
            .await
        });
        Server {
            host,
            calls,
            instance,
            handle,
            task,
        }
    }

    fn host(url: &str) -> HostRec {
        HostRec {
            id: "host-one".into(),
            url: url.into(),
            token: "admin-only".into(),
            tls_fingerprint: "ab".repeat(32),
            ..Default::default()
        }
    }

    #[test]
    fn refuses_insecure_destinations_and_credential_role_reuse() {
        for url in [
            "http://localhost",
            "https://user:pass@localhost",
            "https://localhost/path",
            "https://localhost/?q=secret",
            "https://localhost/#fragment",
        ] {
            assert!(matches!(
                HostTransport::new(&host(url), "installer", "execution", Duration::from_secs(5)),
                Err(Error::Configuration)
            ));
        }
        for (installer, execution) in [
            ("", "execution"),
            ("same", "same"),
            ("admin-only", "execution"),
            ("installer", "admin-only"),
            ("installer\nsecret", "execution"),
        ] {
            assert!(matches!(
                HostTransport::new(
                    &host("https://localhost"),
                    installer,
                    execution,
                    Duration::from_secs(5)
                ),
                Err(Error::Configuration)
            ));
        }
        let mut unpinned = host("https://localhost");
        unpinned.tls_fingerprint.clear();
        assert!(matches!(
            HostTransport::new(&unpinned, "installer", "execution", Duration::from_secs(5)),
            Err(Error::Configuration)
        ));
    }

    #[test]
    fn dedicated_endpoint_preserves_registry_identity_pin_and_administrator() {
        let registered = host("https://localhost:7420");
        let channel = HostTransport::with_endpoint(
            &registered,
            "https://localhost:7441",
            "installer",
            "execution",
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(channel.host_id(), registered.id);
        assert_eq!(channel.administrator_token(), registered.token);
        assert_eq!(channel.origin.port(), Some(7441));
        assert_eq!(registered.url, "https://localhost:7420");
        let mut unpinned = registered.clone();
        unpinned.tls_fingerprint.clear();
        assert!(HostTransport::with_endpoint(
            &unpinned,
            "https://localhost:7441",
            "installer",
            "execution",
            Duration::from_secs(5)
        )
        .is_err());
    }
    #[tokio::test]
    async fn pinned_requests_use_fixed_routes_and_only_their_role_credential() {
        let server = server();
        let transport = HostTransport::new(
            &server.host,
            "installer",
            "execution",
            Duration::from_secs(5),
        )
        .unwrap();
        transport
            .call::<_, serde_json::Value>(Route::Instance, &())
            .await
            .unwrap();
        transport
            .call::<_, serde_json::Value>(Route::Prepare, &())
            .await
            .unwrap();
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Protect, &())
                .await,
            Err(Error::Unconfirmed)
        );
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Dispatch, &())
                .await,
            Err(Error::Unconfirmed)
        );
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Status, &())
                .await,
            Err(Error::Unconfirmed)
        );
        assert_eq!(
            *server.calls.lock().unwrap(),
            [
                (
                    "/internal/execution/v1/instance".into(),
                    "Bearer installer".into()
                ),
                (
                    "/internal/execution/v1/prepare".into(),
                    "Bearer execution".into()
                ),
                (
                    "/internal/execution/v1/protect".into(),
                    "Bearer installer".into()
                ),
                (
                    "/internal/execution/v1/dispatch".into(),
                    "Bearer execution".into()
                ),
                (
                    "/internal/execution/v1/status".into(),
                    "Bearer execution".into()
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_wrong_pin_never_sends_credentials_and_oversized_input_is_not_sent() {
        let mut server = server();
        server.host.tls_fingerprint = "cd".repeat(32);
        let transport = HostTransport::new(
            &server.host,
            "installer",
            "execution",
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Instance, &())
                .await,
            Err(Error::Unconfirmed)
        );
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Prepare, &"x".repeat(MAX_BODY))
                .await,
            Err(Error::Request)
        );
        assert!(server.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_mib_of_json_control_bytes_fits_in_both_directions() {
        let server = server();
        let transport = HostTransport::new(
            &server.host,
            "installer",
            "execution",
            Duration::from_secs(5),
        )
        .unwrap();
        let request = api::ExecRequest {
            cmd: vec!["true".into()],
            stdin: "\0".repeat(1024 * 1024),
            ..Default::default()
        };
        assert!(serde_json::to_vec(&request).unwrap().len() > 6 * 1024 * 1024);
        let result: api::ExecResult = transport.call(Route::Register, &request).await.unwrap();
        assert_eq!(result.stdout, request.stdin);
        assert_eq!(server.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn only_dispatch_accepts_large_capture_replies_and_retains_a_response_ceiling() {
        for route in [
            Route::Instance,
            Route::Register,
            Route::Discover,
            Route::Ownership,
            Route::Protect,
            Route::Delegation,
            Route::Invalidate,
            Route::Revoke,
            Route::Prepare,
            Route::Status,
        ] {
            assert_eq!(route.response_limit(), MAX_BODY);
        }
        assert_eq!(Route::Dispatch.response_limit(), 64 * 1024 * 1024);
        let server = server();
        let transport = HostTransport::new(
            &server.host,
            "installer",
            "execution",
            Duration::from_secs(20),
        )
        .unwrap();
        let result: api::ExecResult = transport
            .call(Route::Dispatch, &"capture_control_bytes")
            .await
            .unwrap();
        assert_eq!(
            result.stdout.len(),
            api::execution::MAX_CAPTURE_BYTES as usize
        );
        assert_eq!(
            result.stderr.len(),
            api::execution::MAX_CAPTURE_BYTES as usize
        );
        assert!(serde_json::to_vec(&result).unwrap().len() > MAX_BODY);
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Dispatch, &"oversized")
                .await,
            Err(Error::Unconfirmed)
        );
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Status, &())
                .await,
            Err(Error::Unconfirmed)
        );
        assert_eq!(
            transport
                .call::<_, serde_json::Value>(Route::Dispatch, &"x".repeat(MAX_BODY))
                .await,
            Err(Error::Request)
        );
    }
}
