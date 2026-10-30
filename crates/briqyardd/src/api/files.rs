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

pub(super) async fn put(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, AppError> {
    wire::check_path(&q.path).map_err(invalid)?;
    let mode = wire::mode(q.mode.as_deref()).map_err(invalid)?;
    let size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| invalid("Content-Length is required"))?;
    wire::check_size(size).map_err(invalid)?;
    let _permit = permit()?;
    let result = tokio::time::timeout(Duration::from_secs(wire::TRANSFER_SEC), async {
        let (mut conn, _, _in_use) = st
            .mgr
            .file_stream(
                &id,
                guest::Request {
                    op: "put_stream".into(),
                    path: q.path,
                    mode,
                    size: Some(size),
                    ..Default::default()
                },
            )
            .await?;
        upload(&mut conn, body, size).await
    })
    .await
    .map_err(|_| invalid("file transfer timeout"))?;
    result?;
    Ok(StatusCode::NO_CONTENT)
}

/// No commit byte is sent until the HTTP body reports a successful end.
async fn upload(conn: &mut impl crate::guestc::Conn, body: Body, size: u64) -> Result<(), MError> {
    let mut stream = body.into_data_stream();
    let mut left = size;
    while let Some(chunk) = idle(stream.next()).await? {
        let chunk = chunk.map_err(|e| MError::Invalid(format!("file body: {e}")))?;
        if chunk.len() as u64 > left {
            return Err(MError::Invalid("file body exceeds Content-Length".into()));
        }
        idle(conn.write_all(&chunk))
            .await?
            .map_err(|e| MError::Other(e.into()))?;
        left -= chunk.len() as u64;
    }
    if left != 0 {
        return Err(MError::Invalid(
            "file body shorter than Content-Length".into(),
        ));
    }
    idle(conn.write_all(&[1]))
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
    Ok::<_, MError>(())
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
            assert!(upload(&mut host, body, 8).await.is_err());
            drop(host);
            let mut received = Vec::new();
            guest.read_to_end(&mut received).await.unwrap();
            assert!(
                !received.contains(&1),
                "no commit marker after a failed body"
            );
        }
    }

    #[tokio::test]
    async fn upload_waits_for_the_guest_ack_after_complete_body() {
        let (mut host, mut guest) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            let mut received = [0; 6];
            guest.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"bytes\x01");
            guest
                .write_all(&guest::encode_frame(&guest::Response::new("ok")).unwrap())
                .await
                .unwrap();
        });
        upload(&mut host, Body::from("bytes"), 5).await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_upload_body_expires_without_a_commit() {
        let (mut host, mut guest) = tokio::io::duplex(1024);
        let body = Body::from_stream(futures::stream::pending::<Result<Vec<u8>, std::io::Error>>());
        let err = upload(&mut host, body, 1).await.unwrap_err();
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
}
