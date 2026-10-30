//! Streaming file forwarding bypasses JSON buffering and keeps lengths and query encoding.
use super::*;

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn file_bytes_stream_through_the_fleet_above_the_json_limit() {
    let data: Vec<u8> = (0..(5 << 20)).map(|n| (n % 251) as u8).collect();
    let expected = data.clone();
    let daemon = Router::new().route(
        "/v1/machines/m1/files/content",
        get(move |req: Request| {
            let data = data.clone();
            async move {
                assert_eq!(req.uri().query(), Some("path=%2Ftmp%2Fa+%26+b"));
                assert_eq!(req.headers()[header::AUTHORIZATION], "Bearer host-token");
                ([(header::CONTENT_TYPE, "application/octet-stream")], data)
            }
        })
        .put(move |req: Request| {
            let expected = expected.clone();
            async move {
                assert_eq!(
                    req.headers()[header::CONTENT_LENGTH],
                    expected.len().to_string()
                );
                let actual = axum::body::to_bytes(req.into_body(), 6 << 20)
                    .await
                    .unwrap();
                assert_eq!(actual.as_ref(), expected);
                StatusCode::NO_CONTENT
            }
        }),
    );
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let _server = Server(tokio::spawn(async move {
        axum::serve(ln, daemon).await.unwrap();
    }));
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![config::StaticHost {
            id: "h1".into(),
            url: format!("http://{addr}"),
            token: "host-token".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert("m1".into(), "h1".into());
    let route = app(f.st.clone());
    let response = route
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/machines/m1/files/content?path=%2Ftmp%2Fa+%26+b")
                .header(header::AUTHORIZATION, "Bearer api")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-briqyard-host"], "h1");
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        (5 << 20).to_string()
    );
    let bytes = axum::body::to_bytes(response.into_body(), 6 << 20)
        .await
        .unwrap();
    assert_eq!(bytes.len(), 5 << 20);
    let response = route
        .oneshot(
            axum::http::Request::builder()
                .method(Method::PUT)
                .uri("/v1/machines/m1/files/content?path=%2Ffile")
                .header(header::AUTHORIZATION, "Bearer api")
                .header(header::CONTENT_LENGTH, bytes.len())
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn missing_or_oversize_lengths_are_refused_before_forwarding() {
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![config::StaticHost {
            id: "h1".into(),
            url: "http://127.0.0.1:1".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert("m1".into(), "h1".into());
    for size in [None, Some(api::files::MAX_SIZE + 1)] {
        let mut req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri("/v1/machines/m1/files/content?path=%2Ffile")
            .header(header::AUTHORIZATION, "Bearer api");
        if let Some(size) = size {
            req = req.header(header::CONTENT_LENGTH, size);
        }
        let response = app(f.st.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
