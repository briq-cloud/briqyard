//! Provisioned fixed HTTPS continuation callback. Request credentials and routing
//! never come from execution grants, operation IDs or gateway input.
use crate::{
    config::Continuation,
    execution_service::renewal::{ContinuationError, ContinuationProvider},
};
use briqyard_api::execution::provision;
use reqwest::{header, Client, Url};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub(super) struct HttpsContinuation {
    client: Client,
    url: Url,
    authorization: header::HeaderValue,
}
#[derive(Serialize)]
struct Request<'a> {
    operation_id: &'a str,
    previous_sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    state: State,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum State {
    Continued,
    Recovered,
    NotNeeded,
}
impl HttpsContinuation {
    pub fn new(
        config: &Continuation,
        roles: &provision::Credentials,
    ) -> Result<Self, &'static str> {
        let url = Url::parse(&config.url).map_err(|_| "invalid continuation callback")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() == "/"
            || !config.credential_file.is_absolute()
        {
            return Err("invalid continuation callback");
        }
        let bytes = provision::read(&config.credential_file, true, 4096)?;
        let credential = String::from_utf8(bytes).map_err(|_| "invalid continuation credential")?;
        if credential.is_empty()
            || credential.bytes().any(|b| !b.is_ascii_graphic())
            || [
                &roles.host_installer,
                &roles.host_execution,
                &roles.central_installer,
                &roles.gateway,
                &roles.host_administrator,
                &roles.fleet_administrator,
            ]
            .contains(&&credential)
        {
            return Err("invalid continuation credential");
        }
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {credential}"))
            .map_err(|_| "invalid continuation credential")?;
        authorization.set_sensitive(true);
        let client = transport(None)?;
        Ok(Self {
            client,
            url,
            authorization,
        })
    }
    async fn send(
        &self,
        operation_id: &str,
        previous_sequence: u64,
    ) -> Result<(), ContinuationError> {
        let body = serde_json::to_vec(&Request {
            operation_id,
            previous_sequence,
        })
        .map_err(|_| ContinuationError::Unconfirmed)?;
        if body.len() > 4096 {
            return Err(ContinuationError::Unconfirmed);
        }
        let operation = async {
            let mut response = self
                .client
                .post(self.url.clone())
                .header(header::AUTHORIZATION, self.authorization.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|_| ContinuationError::Unconfirmed)?;
            if response.status() != reqwest::StatusCode::OK
                || response.content_length().is_some_and(|n| n > 4096)
            {
                return Err(ContinuationError::Unconfirmed);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| ContinuationError::Unconfirmed)?
            {
                if bytes.len() + chunk.len() > 4096 {
                    return Err(ContinuationError::Unconfirmed);
                }
                bytes.extend_from_slice(&chunk);
            }
            let reply: Reply =
                serde_json::from_slice(&bytes).map_err(|_| ContinuationError::Unconfirmed)?;
            match reply.state {
                State::Continued | State::Recovered | State::NotNeeded => Ok(()),
            }
        };
        tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .map_err(|_| ContinuationError::Unconfirmed)?
    }
}
fn transport(root: Option<reqwest::Certificate>) -> Result<Client, &'static str> {
    let mut client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    if let Some(root) = root {
        client = client.add_root_certificate(root);
    }
    client.build().map_err(|_| "invalid continuation transport")
}
impl ContinuationProvider for HttpsContinuation {
    fn request<'a>(
        &'a self,
        operation_id: &'a str,
        previous_sequence: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), ContinuationError>> + Send + 'a>,
    > {
        Box::pin(self.send(operation_id, previous_sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn roles() -> provision::Credentials {
        provision::Credentials {
            host_installer: "host-installer".into(),
            host_execution: "host-execution".into(),
            central_installer: "central-installer".into(),
            gateway: "gateway".into(),
            host_administrator: "host-admin".into(),
            fleet_administrator: "fleet-admin".into(),
        }
    }
    #[test]
    fn callback_is_fixed_https_and_credential_is_a_distinct_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("callback");
        std::fs::write(&path, b"callback-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut config = Continuation {
            url: "https://example.invalid/internal/continue".into(),
            credential_file: path.clone(),
        };
        assert!(HttpsContinuation::new(&config, &roles()).is_ok());
        for url in [
            "http://example.invalid/continue",
            "https://user@example.invalid/continue",
            "https://example.invalid/continue?x=1",
            "https://example.invalid/continue#x",
            "https://example.invalid/",
        ] {
            config.url = url.into();
            assert!(HttpsContinuation::new(&config, &roles()).is_err());
        }
        config.url = "https://example.invalid/continue".into();
        for credential in [
            "",
            "callback\n",
            "host-installer",
            "host-execution",
            "central-installer",
            "gateway",
            "host-admin",
            "fleet-admin",
        ] {
            std::fs::write(&path, credential).unwrap();
            assert!(HttpsContinuation::new(&config, &roles()).is_err());
        }
        std::fs::write(&path, "callback-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(HttpsContinuation::new(&config, &roles()).is_err());
    }
    #[tokio::test]
    async fn callback_sends_once_and_refuses_redirect_failure_and_oversized_reply() {
        use axum::{
            extract::State,
            http::{HeaderMap, StatusCode},
            response::IntoResponse,
            routing::post,
            Json, Router,
        };
        use std::sync::{Arc, Mutex};
        type Calls = Arc<Mutex<Vec<serde_json::Value>>>;
        async fn endpoint(
            State(calls): State<Calls>,
            headers: HeaderMap,
            Json(body): Json<serde_json::Value>,
        ) -> axum::response::Response {
            assert_eq!(
                headers.get(header::AUTHORIZATION).unwrap(),
                "Bearer callback-only"
            );
            calls.lock().unwrap().push(body.clone());
            match body["operation_id"].as_str().unwrap() {
                "redirect" => (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, "/callback")],
                )
                    .into_response(),
                "failure" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                "oversized" => "x".repeat(4097).into_response(),
                "pending" => Json(serde_json::json!({"state":"pending"})).into_response(),
                _ => Json(serde_json::json!({"state":"continued"})).into_response(),
            }
        }
        struct Server {
            handle: axum_server::Handle,
            task: tokio::task::JoinHandle<std::io::Result<()>>,
        }
        impl Drop for Server {
            fn drop(&mut self) {
                self.handle.shutdown();
                self.task.abort();
            }
        }
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let tls = briqyard_api::tls::server_config(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Calls::default();
        let app = Router::new()
            .route("/callback", post(endpoint))
            .with_state(calls.clone());
        let handle = axum_server::Handle::new();
        let run_handle = handle.clone();
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(
                listener,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
            )
            .handle(run_handle)
            .serve(app.into_make_service())
            .await
        });
        let _server = Server { handle, task };
        let mut authorization = header::HeaderValue::from_static("Bearer callback-only");
        authorization.set_sensitive(true);
        let provider = HttpsContinuation {
            client: transport(Some(
                reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap(),
            ))
            .unwrap(),
            url: Url::parse(&format!("https://{address}/callback")).unwrap(),
            authorization,
        };
        provider.send("operation", 3).await.unwrap();
        for operation in ["redirect", "failure", "oversized", "pending"] {
            assert!(provider.send(operation, 3).await.is_err());
        }
        assert_eq!(
            calls.lock().unwrap().len(),
            5,
            "failures and redirects never replay"
        );
        assert_eq!(
            calls.lock().unwrap()[0],
            serde_json::json!({"operation_id":"operation","previous_sequence":3})
        );
    }

    #[test]
    fn callback_success_is_strict_and_carries_neither_tokens_nor_source_times() {
        assert_eq!(
            serde_json::to_value(Request {
                operation_id: "operation",
                previous_sequence: 0
            })
            .unwrap(),
            serde_json::json!({"operation_id":"operation","previous_sequence":0})
        );
        for state in ["continued", "recovered", "not-needed"] {
            assert!(serde_json::from_value::<Reply>(serde_json::json!({"state":state})).is_ok());
        }
        for reply in [
            serde_json::json!({"state":"pending"}),
            serde_json::json!({"state":"unknown"}),
            serde_json::json!({"state":"continued","continuation":"token"}),
            serde_json::json!({"state":null}),
        ] {
            assert!(serde_json::from_value::<Reply>(reply).is_err());
        }
    }
}
