//! Authentication and the request line.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct IsError;

pub(super) async fn auth_and_log(State(st): S, req: Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| {
            use rand::RngCore;
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            hex::encode(b)
        });
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // The tokens that open the path; none set, nothing is asked.
    let accepted: Vec<&str> = match bearer_for(&path, st.loopback) {
        Bearer::None => vec![],
        Bearer::Api => vec![st.token.as_str()],
        Bearer::MetricsOrApi => vec![st.metrics_token.as_str(), st.token.as_str()],
    }
    .into_iter()
    .filter(|t| !t.is_empty())
    .collect();
    if !accepted.is_empty() {
        let got = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let known = accepted
            .iter()
            .any(|t| api::constant_eq(got.as_bytes(), t.as_bytes()));
        if !known {
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(api::ApiError {
                    error: "a bearer token is required".into(),
                    code: "unauthorized".into(),
                    request_id: request_id.clone(),
                    machine: None,
                    oldest: None,
                }),
            )
                .into_response();
            resp.headers_mut()
                .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
            return resp;
        }
    }
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
    if path != "/healthz" {
        tracing::info!(%method, path, status = resp.status().as_u16(), ms = start.elapsed().as_millis() as u64, request_id, "request");
    }
    resp
}
