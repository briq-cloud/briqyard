//! The v1 control path stays responsive while downstream output is blocked.
use super::*;
use std::collections::VecDeque;

pub(super) async fn pump<Rx, Tx>(
    mut from_client: Rx,
    mut to_client: Tx,
    conn: Box<dyn guestc::Conn>,
    heartbeat: Duration,
) -> Ended
where
    Rx: Stream<Item = Result<Message, axum::Error>> + Unpin,
    Tx: Sink<Message> + Unpin + Send + 'static,
{
    let (mut guest_read, mut guest_write) = tokio::io::split(conn);
    let (guest_tx, mut guest_rx) = tokio::sync::mpsc::channel::<Response>(16);
    let reader = tokio::spawn(async move {
        while let Ok(response) = guestc::read_frame(&mut guest_read).await {
            if guest_tx.send(response).await.is_err() {
                break;
            }
        }
    });
    let gone_after = 3 * heartbeat;
    let (output, mut output_rx) = tokio::sync::mpsc::channel::<Message>(16);
    let (failed_tx, mut failed) = tokio::sync::oneshot::channel();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
    let writer = tokio::spawn(async move {
        while let Some(message) = output_rx.recv().await {
            if !send(&mut to_client, message, gone_after).await {
                let _ = failed_tx.send(());
                return;
            }
        }
        let _ = close_rx.await;
    });
    let mut pending = VecDeque::new();
    let mut beat = tokio::time::interval_at(Instant::now() + heartbeat, heartbeat);
    let mut heard = Instant::now();
    let mut cancelled = false;
    let end = loop {
        tokio::select! {
            _ = &mut failed => break None,
            permit = output.reserve(), if !pending.is_empty() => {
                match permit { Ok(permit) => permit.send(pending.pop_front().unwrap()), Err(_) => break None }
            }
            response = guest_rx.recv(), if pending.len() < 16 => {
                let Some(response) = response else {
                    break Some(SessionEnd::failed("not_running", "the machine went down during the command"));
                };
                let channel = match response.kind.as_str() {
                    "stdout" => channel::STDOUT,
                    "stderr" => channel::STDERR,
                    "exit" => break Some(SessionEnd {
                        exit_code: Some(response.code), timed_out: response.timed_out,
                        cancelled: response.cancelled, ..Default::default()
                    }),
                    "error" => break Some(SessionEnd::failed(
                        if response.error_code.is_empty() { "internal" } else { &response.error_code }, response.message)),
                    _ => continue,
                };
                pending.push_back(Message::Binary(wire::message(channel, &response.data)));
            }
            message = from_client.next() => {
                heard = Instant::now();
                match message {
                    Some(Ok(Message::Text(text))) => {
                        if serde_json::from_str::<wire::stream::Control>(&text).is_err() {
                            break Some(SessionEnd::failed("invalid", "only cancel is accepted after the initial request"));
                        }
                        if !cancelled {
                            cancelled = true;
                            let cancel = Request { op: "cancel".into(), ..Default::default() };
                            if !matches!(tokio::time::timeout(Duration::from_secs(1), guestc::write_request(&mut guest_write, &cancel)).await, Ok(Ok(()))) {
                                break Some(SessionEnd::failed("not_running", "cancellation acknowledgment unavailable"));
                            }
                        }
                    }
                    Some(Ok(Message::Binary(_))) => break Some(SessionEnd::failed("invalid", "data and resize are not supported")),
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break None,
                    Some(Ok(_)) => {}
                }
            }
            _ = beat.tick() => {
                if heard.elapsed() > gone_after { break None; }
                if pending.len() < 16 { pending.push_back(Message::Ping(Vec::new())); }
            }
        }
    };
    // Both guest halves go before any failure is reported or closing handshake begins.
    reader.abort();
    let _ = reader.await;
    drop(guest_write);
    drop(guest_rx);
    let Some(end) = end else {
        writer.abort();
        let _ = writer.await;
        return Ended::ClientGone;
    };
    let terminal = Message::Binary(wire::message(
        channel::EXIT,
        &serde_json::to_vec(&end).unwrap_or_default(),
    ));
    pending.push_back(terminal);
    pending.push_back(Message::Close(Some(CloseFrame {
        code: 1000,
        reason: "".into(),
    })));
    let flush = async {
        while let Some(message) = pending.pop_front() {
            if output.send(message).await.is_err() {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(gone_after, flush).await;
    drop(output);
    // Keep the WebSocket until the client acknowledges close, after the guest is gone.
    let closed = async {
        while let Some(Ok(message)) = from_client.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(gone_after, closed).await;
    let _ = close_tx.send(());
    // A bounded flush and owned writer: no detached output tasks after the session.
    let mut writer = writer;
    if tokio::time::timeout(gone_after, &mut writer).await.is_err() {
        writer.abort();
        let _ = writer.await;
    }
    Ended::Command(end)
}
