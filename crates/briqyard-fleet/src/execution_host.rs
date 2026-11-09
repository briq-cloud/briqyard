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
        if host.id.is_empty()
            || installer.is_empty()
            || execution.is_empty()
            || installer == execution
            || installer == host.token
            || execution == host.token
            || timeout.is_zero()
            || timeout > Duration::from_secs(300)
        {
            return Err(Error::Configuration);
        }
        let origin = Url::parse(&host.url).map_err(|_| Error::Configuration)?;
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
            api::tls::parse_fingerprint(&host.tls_fingerprint).map_err(|_| Error::Configuration)?;
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
            administrator: host.token.clone(),
            host_id: host.id.clone(),
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
        let mut response = request.send().await.map_err(|_| Error::Unconfirmed)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|len| len > MAX_BODY as u64)
        {
            return Err(Error::Unconfirmed);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unconfirmed)? {
            if chunk.len() > MAX_BODY - body.len() {
                return Err(Error::Unconfirmed);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::Unconfirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode, Uri},
        response::IntoResponse,
        Router,
    };
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<(String, String)>>>;

    struct Server {
        host: HostRec,
        calls: Calls,
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
        State(calls): State<Calls>,
        uri: Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        calls.lock().unwrap().push((
            uri.path().into(),
            headers[header::AUTHORIZATION].to_str().unwrap().into(),
        ));
        match uri.path() {
            "/internal/execution/v1/protect" => (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "/unexpected")],
                "{}",
            )
                .into_response(),
            "/internal/execution/v1/dispatch" => {
                (StatusCode::SERVICE_UNAVAILABLE, "{}").into_response()
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

    fn server() -> Server {
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
        let router = Router::new()
            .fallback(endpoint)
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
            .with_state(calls.clone());
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
}
