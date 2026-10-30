//! Argument parsing, the tables, and the client against a stub API on loopback.

use super::*;
use clap::error::ErrorKind;
use clap::Parser;

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("briqyard").chain(args.iter().copied()))
        .unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

fn fails(args: &[&str]) -> ErrorKind {
    match Cli::try_parse_from(std::iter::once("briqyard").chain(args.iter().copied())) {
        Ok(_) => panic!("{args:?} parsed"),
        Err(e) => e.kind(),
    }
}

fn machine(cli: Cli) -> MachineCmd {
    match cli.cmd {
        Cmd::Machine(m) => *m,
        _ => panic!("not a machine command"),
    }
}

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: String,
}

/// Response headers of a canned reply.
type Headers = Vec<(&'static str, &'static str)>;

/// An API on loopback: records every request and answers the next canned reply (status,
/// headers, body); 500 when none is left.
struct Stub {
    seen: Mutex<Vec<Seen>>,
    replies: Mutex<VecDeque<(StatusCode, Headers, String)>>,
}

/// A header's value. A function, not a closure: a closure keeping `&req` while the body is
/// read would hold a `!Sync` body across the await and the handler would not be `Send`.
fn header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

async fn answer(State(stub): State<Arc<Stub>>, req: Request) -> axum::response::Response {
    let mut seen = Seen {
        method: req.method().to_string(),
        path: req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default(),
        authorization: header(&req, "authorization"),
        content_type: header(&req, "content-type"),
        body: String::new(),
    };
    let data = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap();
    seen.body = String::from_utf8_lossy(&data).into_owned();
    stub.seen.lock().unwrap().push(seen);
    let next = stub.replies.lock().unwrap().pop_front();
    match next {
        Some((status, headers, body)) => {
            let mut resp = (status, body).into_response();
            for (k, v) in headers {
                resp.headers_mut().insert(k, v.parse().unwrap());
            }
            resp
        }
        None => (StatusCode::INTERNAL_SERVER_ERROR, "no canned reply").into_response(),
    }
}

async fn stub(replies: Vec<(StatusCode, Headers, &str)>) -> (String, Arc<Stub>) {
    let stub = Arc::new(Stub {
        seen: Mutex::new(vec![]),
        replies: Mutex::new(
            replies
                .into_iter()
                .map(|(s, h, b)| (s, h, b.to_string()))
                .collect(),
        ),
    });
    let app = axum::Router::new()
        .fallback(answer)
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, stub)
}

fn client(base: &str, token: Option<&str>) -> Client {
    Client {
        base: base.trim_end_matches('/').to_string(),
        token: token.map(|t| t.to_string()),
        // A stub that never answers fails its test rather than holding it forever.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap(),
    }
}

const JSON: &[(&str, &str)] = &[("content-type", "application/json")];
fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-19T08:30:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

mod client;
mod commands;
mod doctor;
mod events;
mod labels;
mod parsing;
mod sessions;
mod tables;
