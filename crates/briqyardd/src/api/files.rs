//! Bounded HTTP file streams: no whole-file buffering on either transport.

use super::*;
use briqyard_api::{files as wire, guest};
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

static TRANSFERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(wire::MAX_TRANSFERS);

#[derive(Deserialize)]
pub(super) struct FileQuery {
    path: String,
    mode: Option<String>,
}

fn invalid(e: impl Into<String>) -> AppError {
    MError::Invalid(e.into()).into()
}

fn permit() -> Result<tokio::sync::SemaphorePermit<'static>, AppError> {
    TRANSFERS
        .try_acquire()
        .map_err(|_| MError::Conflict("too many file transfers".into()).into())
}

pub(super) async fn capabilities(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<wire::FileCapabilities>, AppError> {
    Ok(Json(st.mgr.file_capabilities(&id).await?))
}

pub(super) async fn put(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<wire::FileWriteResponse>, AppError> {
    wire::check_path(&q.path).map_err(invalid)?;
    let mode = q
        .mode
        .as_deref()
        .map(|m| wire::mode(Some(m)))
        .transpose()
        .map_err(invalid)?;
    let size = headers
        .get(header::CONTENT_LENGTH)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| invalid("invalid Content-Length"))
        })
        .transpose()?;
    if let Some(size) = size {
        wire::check_size(size).map_err(invalid)?;
    }
    let _permit = permit()?;
    let result = tokio::time::timeout(Duration::from_secs(wire::TRANSFER_SEC), async {
        let (mut conn, _, _in_use) = st
            .mgr
            .file_stream(
                &id,
                guest::Request {
                    op: "put_stream".into(),
                    path: q.path,
                    file_mode: mode,
                    size,
                    ..Default::default()
                },
            )
            .await?;
        upload(&mut conn, body, size).await
    })
    .await
    .map_err(|_| invalid("file transfer timeout"))?;
    Ok(Json(result?))
}

/// No terminal chunk is sent until the HTTP body reports a successful end.
async fn upload(
    conn: &mut impl crate::guestc::Conn,
    body: Body,
    size: Option<u64>,
) -> Result<wire::FileWriteResponse, MError> {
    let mut stream = body.into_data_stream();
    let mut total = 0u64;
    while let Some(chunk) = idle(stream.next()).await? {
        let chunk = chunk.map_err(|e| MError::Invalid(format!("file body: {e}")))?;
        let next = wire::streamed_size(total, chunk.len() as u64, size).map_err(MError::Invalid)?;
        for piece in chunk.chunks(wire::CHUNK_SIZE) {
            idle(conn.write_u32(piece.len() as u32))
                .await?
                .map_err(|e| MError::Other(e.into()))?;
            idle(conn.write_all(piece))
                .await?
                .map_err(|e| MError::Other(e.into()))?;
        }
        total = next;
    }
    if size.is_some_and(|size| size != total) {
        return Err(MError::Invalid(
            "file body shorter than Content-Length".into(),
        ));
    }
    idle(conn.write_u32(0))
        .await?
        .map_err(|e| MError::Other(e.into()))?;
    let response: guest::Response = idle(crate::guestc::read_frame(conn))
        .await?
        .map_err(MError::Other)?;
    if response.kind != "ok" {
        return Err(MError::Other(anyhow::anyhow!(
            "upload: {}",
            response.message
        )));
    }
    if response.size != Some(total)
        || response.sha256.len() != 64
        || !response.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(MError::Other(anyhow::anyhow!(
            "guest returned invalid upload result"
        )));
    }
    Ok(wire::FileWriteResponse {
        size: total,
        sha256: response.sha256,
    })
}

async fn idle<T>(f: impl std::future::Future<Output = T>) -> Result<T, MError> {
    tokio::time::timeout(Duration::from_secs(wire::IDLE_SEC), f)
        .await
        .map_err(|_| MError::NotRunning("file stream idle timeout".into()))
}

pub(super) async fn get(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Result<Response, AppError> {
    wire::check_path(&q.path).map_err(invalid)?;
    let permit = permit()?;
    let deadline = Instant::now() + Duration::from_secs(wire::TRANSFER_SEC);
    let (conn, size, in_use) = st
        .mgr
        .file_stream(
            &id,
            guest::Request {
                op: "get_stream".into(),
                path: q.path,
                ..Default::default()
            },
        )
        .await?;
    let size = size.ok_or_else(|| invalid("guest omitted file size"))?;
    wire::check_size(size).map_err(invalid)?;
    let mut response = download(conn, size, (in_use, permit), deadline).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    Ok(response)
}

/// The guard and guest belong to the bounded pump, so an unpolled body cannot retain use.
fn download(
    conn: impl crate::guestc::Conn + 'static,
    size: u64,
    guard: impl Send + 'static,
    deadline: Instant,
) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let guard = guard;
        let mut conn = conn;
        let transfer = async {
            let mut left = size;
            while left > 0 {
                let mut buf = vec![0; (left as usize).min(wire::CHUNK_SIZE)];
                let n = idle(conn.read(&mut buf))
                    .await?
                    .map_err(|e| MError::Other(e.into()))?;
                if n == 0 {
                    return Err(MError::Other(anyhow::anyhow!("file stream ended early")));
                }
                buf.truncate(n);
                left -= n as u64;
                idle(tx.send(buf))
                    .await?
                    .map_err(|_| MError::Other(anyhow::anyhow!("file reader closed")))?;
            }
            Ok::<_, MError>(())
        };
        let result = tokio::select! {
            _ = tx.closed() => return,
            r = tokio::time::timeout_at(deadline, transfer) => r.unwrap_or_else(|_| Err(MError::NotRunning("file transfer timeout".into()))),
        };
        // The outcome has its own slot: a queued chunk cannot hide a later short read.
        drop(conn);
        drop(guard);
        let _ = done_tx.send(result.map_err(|e| std::io::Error::other(e.to_string())));
    });
    let stream = futures::stream::unfold((rx, Some(done_rx)), |(mut rx, mut done)| async move {
        if let Some(chunk) = rx.recv().await {
            return Some((Ok(chunk), (rx, done)));
        }
        if let Some(done) = done.take() {
            match done.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Some((Err(e), (rx, None))),
                Err(_) => {
                    return Some((
                        Err(std::io::Error::other("file transfer interrupted")),
                        (rx, None),
                    ))
                }
            }
        }
        None
    });
    Body::from_stream(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bad_http_bodies_never_commit_the_guest_file() {
        for body in [
            Body::from("short"),
            Body::from("longer than promised"),
            Body::from_stream(futures::stream::iter([
                Ok::<_, std::io::Error>(b"bytes".to_vec()),
                Err(std::io::Error::other("disconnected")),
            ])),
        ] {
            let (mut host, mut guest) = tokio::io::duplex(1024);
            assert!(upload(&mut host, body, Some(8)).await.is_err());
            drop(host);
            let mut received = Vec::new();
            guest.read_to_end(&mut received).await.unwrap();
            let mut rest = received.as_slice();
            while rest.len() >= 4 {
                let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                assert!(length > 0, "no terminal chunk after a failed body");
                assert!(rest.len() >= 4 + length);
                rest = &rest[4 + length..];
            }
            assert!(rest.is_empty());
        }
    }

    #[tokio::test]
    async fn upload_waits_for_the_guest_ack_after_complete_body() {
        for declared in [None, Some(5)] {
            let (mut host, mut guest) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move {
                let mut received = [0; 13];
                guest.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"\0\0\0\x05bytes\0\0\0\0");
                guest
                    .write_all(
                        &guest::encode_frame(&guest::Response {
                            kind: "ok".into(),
                            size: Some(5),
                            sha256: "a".repeat(64),
                            ..Default::default()
                        })
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            });
            let written = upload(&mut host, Body::from("bytes"), declared)
                .await
                .unwrap();
            assert_eq!(written.size, 5);
            assert_eq!(written.sha256, "a".repeat(64));
            task.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn silent_upload_body_expires_without_a_commit() {
        let (mut host, mut guest) = tokio::io::duplex(1024);
        let body = Body::from_stream(futures::stream::pending::<Result<Vec<u8>, std::io::Error>>());
        let err = upload(&mut host, body, Some(1)).await.unwrap_err();
        assert!(err.to_string().contains("idle timeout"));
        drop(host);
        let mut bytes = Vec::new();
        guest.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
    struct Guard(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(done) = self.0.take() {
                let _ = done.send(());
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unpolled_download_releases_use_after_backpressure_timeout() {
        let (host, mut guest) = tokio::io::duplex(1024);
        let (done, dropped) = tokio::sync::oneshot::channel();
        let body = download(
            host,
            (wire::CHUNK_SIZE * 4) as u64,
            Guard(Some(done)),
            Instant::now() + Duration::from_secs(wire::TRANSFER_SEC),
        );
        let writer =
            tokio::spawn(async move { guest.write_all(&vec![7; wire::CHUNK_SIZE * 4]).await });
        dropped.await.unwrap();
        assert!(
            writer.await.unwrap().is_err(),
            "guest closed while the response body is still retained"
        );
        drop(body);
    }

    #[tokio::test]
    async fn a_dropped_download_closes_the_guest_and_releases_use() {
        let (host, mut guest) = tokio::io::duplex(1024);
        let (done, dropped) = tokio::sync::oneshot::channel();
        let body = download(
            host,
            1,
            Guard(Some(done)),
            Instant::now() + Duration::from_secs(wire::TRANSFER_SEC),
        );
        drop(body);
        tokio::time::timeout(Duration::from_secs(1), dropped)
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        guest.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn a_short_download_fails_the_http_body() {
        let (host, mut guest) = tokio::io::duplex(1024);
        guest.write_all(b"short").await.unwrap();
        drop(guest);
        let body = download(
            host,
            10,
            (),
            Instant::now() + Duration::from_secs(wire::TRANSFER_SEC),
        );
        assert!(axum::body::to_bytes(body, 10).await.is_err());
    }
    #[tokio::test]
    async fn large_unknown_http_chunks_are_split_into_bounded_guest_chunks() {
        let (mut host, mut guest) = tokio::io::duplex(1024);
        let size = wire::CHUNK_SIZE * 2 + 7;
        let task = tokio::spawn(async move {
            for expected in [wire::CHUNK_SIZE, wire::CHUNK_SIZE, 7] {
                let length = guest.read_u32().await.unwrap() as usize;
                assert_eq!(length, expected);
                let mut data = vec![0; length];
                guest.read_exact(&mut data).await.unwrap();
                assert!(data.iter().all(|b| *b == 7));
            }
            assert_eq!(guest.read_u32().await.unwrap(), 0);
            guest
                .write_all(
                    &guest::encode_frame(&guest::Response {
                        kind: "ok".into(),
                        size: Some(size as u64),
                        sha256: "a".repeat(64),
                        ..Default::default()
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        let result = upload(&mut host, Body::from(vec![7; size]), None)
            .await
            .unwrap();
        assert_eq!(result.size, size as u64);
        task.await.unwrap();
    }
}
