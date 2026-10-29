//! Exec sessions (ADR 0029).

use super::*;

/// A daemon's session reduced: stdin back on stdout, a resize as `COLSxROWS`, an exit of 5 at
/// stdin's end; the query and the token it was asked with on stdout first. Not running when the
/// machine is `m_asleep`.
async fn session_stub() -> String {
    use api::session::{channel, message, parse, Resize};
    use axum::extract::ws::{Message, WebSocketUpgrade};
    use axum::extract::{Path, RawQuery};
    use axum::http::HeaderMap;
    async fn exec(
        Path(id): Path<String>,
        RawQuery(q): RawQuery,
        headers: HeaderMap,
        ws: WebSocketUpgrade,
    ) -> axum::response::Response {
        if id == "m_asleep" {
            let body = r#"{"error":"machine is not running: stopped (idle)","code":"not_running"}"#;
            return (
                StatusCode::CONFLICT,
                [("content-type", "application/json")],
                body,
            )
                .into_response();
        }
        let auth = headers
            .get("authorization")
            .map_or("no token", |v| v.to_str().unwrap())
            .to_string();
        ws.on_upgrade(move |mut socket| async move {
            let hello = format!("{} {}\n", q.unwrap_or_default(), auth);
            let _ = socket
                .send(Message::Binary(message(channel::STDOUT, hello.as_bytes())))
                .await;
            while let Some(Ok(Message::Binary(b))) = socket.recv().await {
                let reply = match parse(&b) {
                    Some((channel::STDIN, p)) => message(channel::STDOUT, p),
                    Some((channel::RESIZE, p)) => {
                        let r: Resize = serde_json::from_slice(p).unwrap();
                        message(channel::STDOUT, format!("{}x{}", r.cols, r.rows).as_bytes())
                    }
                    Some((channel::CLOSE, _)) => {
                        message(channel::EXIT, br#"{"exit_code":5,"timed_out":true}"#)
                    }
                    _ => continue,
                };
                let last = reply[0] == channel::EXIT;
                if socket.send(Message::Binary(reply)).await.is_err() || last {
                    break;
                }
            }
        })
    }
    let app = axum::Router::new().route("/v1/machines/:id/exec", axum::routing::get(exec));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

fn session_req(tty: bool) -> api::session::ExecSession {
    api::session::ExecSession {
        cmd: vec!["sh".into(), "-c".into(), "cat".into()],
        tty,
        cols: 100,
        rows: 30,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_session_sends_the_local_side_and_answers_the_remote_code() {
    let url = session_stub().await;
    let c = client(&url, Some("t0k"));
    let ws = session::connect(&c, "m1", &session_req(true))
        .await
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    for l in [
        session::Local::Stdin(b"hi ".to_vec()),
        session::Local::Resize(api::session::Resize {
            cols: 120,
            rows: 40,
        }),
        session::Local::EndOfInput,
    ] {
        tx.send(l).await.unwrap();
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = session::drive(ws, rx, &mut out, &mut err).await.unwrap();
    assert_eq!(code, 5);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "cmd=sh&cmd=-c&cmd=cat&tty=true&cols=100&rows=30 Bearer t0k\nhi 120x40"
    );
    assert_eq!(String::from_utf8(err).unwrap(), "(timed out)\n");
}

#[tokio::test]
async fn a_session_refused_or_stopped_locally() {
    let url = session_stub().await;
    let c = client(&url, None);
    let e = session::connect(&c, "m_asleep", &session_req(false))
        .await
        .err()
        .unwrap();
    assert_eq!(
        e.to_string(),
        "machine is not running: stopped (idle) (not_running)"
    );
    // A signal to the CLI ends the session with its code; the remote command ends with it.
    let ws = session::connect(&c, "m1", &session_req(false))
        .await
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(session::Local::Stop(130)).await.unwrap();
    let mut sink = Vec::new();
    let code = session::drive(ws, rx, &mut sink, &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(code, 130);
}
