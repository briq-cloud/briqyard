//! An exec session's WebSocket (ADR 0029): the client's messages become the guest's input
//! frames, the guest's output frames become messages, and the command's exit is the last one.

use crate::events;
use crate::guestc;
use crate::machine::Session;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use briqyard_api::guest::{Request, Response};
use briqyard_api::session::{self as wire, channel, Resize, SessionEnd};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::time::Duration;
use tokio::time::Instant;

/// How a session ended.
#[derive(Debug, PartialEq)]
pub enum Ended {
    /// The command ended, or the session could not go on: the last message the client got.
    Command(SessionEnd),
    /// The client closed, or was silent past three heartbeats: the command ends with it.
    ClientGone,
}

/// Serves an upgraded session to its end. The machine is in use until then.
pub async fn serve(socket: WebSocket, session: Session) {
    let started = Instant::now();
    let Session {
        conn,
        machine,
        in_use,
    } = session;
    let (to_client, from_client) = socket.split();
    let ended = pump(from_client, to_client, conn, events::HEARTBEAT).await;
    drop(in_use);
    let secs = started.elapsed().as_secs();
    match ended {
        Ended::Command(e) if e.code.is_empty() => {
            tracing::info!(
                machine,
                exit_code = e.exit_code.unwrap_or_default(),
                timed_out = e.timed_out,
                secs,
                "exec session ended"
            )
        }
        Ended::Command(e) => {
            tracing::info!(
                machine,
                code = e.code,
                err = e.error,
                secs,
                "exec session failed"
            )
        }
        Ended::ClientGone => tracing::info!(machine, secs, "exec session left by its client"),
    }
}

/// Carries a session until the command ends or the client goes. A ping goes out every
/// `heartbeat`; a client heard from (anything, its pongs included) in none of the last three
/// is gone, and so is one that takes no message for as long (it stopped reading: a laptop
/// asleep). Dropping `conn` at the end is what ends a command whose client went.
pub async fn pump<Rx, Tx>(
    mut from_client: Rx,
    mut to_client: Tx,
    conn: Box<dyn guestc::Conn>,
    heartbeat: Duration,
) -> Ended
where
    Rx: Stream<Item = Result<Message, axum::Error>> + Unpin,
    Tx: Sink<Message> + Unpin,
{
    let (mut from_guest_io, mut to_guest) = tokio::io::split(conn);
    let (tx, mut from_guest) = tokio::sync::mpsc::channel::<Response>(16);
    // A task of its own: a frame read is not cancel-safe, and the loop below selects.
    let reader = tokio::spawn(async move {
        while let Ok(r) = guestc::read_frame::<_, Response>(&mut from_guest_io).await {
            if tx.send(r).await.is_err() {
                break;
            }
        }
    });
    let gone_after = 3 * heartbeat;
    let mut beat = tokio::time::interval_at(Instant::now() + heartbeat, heartbeat);
    let mut heard = Instant::now();
    let end = loop {
        tokio::select! {
            r = from_guest.recv() => {
                let Some(r) = r else {
                    break Some(SessionEnd::failed(
                        "not_running",
                        "the machine went down during the command",
                    ));
                };
                let ch = match r.kind.as_str() {
                    "stdout" => channel::STDOUT,
                    "stderr" => channel::STDERR,
                    "exit" => break Some(SessionEnd {
                        exit_code: Some(r.code),
                        timed_out: r.timed_out,
                        ..Default::default()
                    }),
                    "error" => break Some(SessionEnd::failed("internal", r.message)),
                    _ => continue,
                };
                if !send(&mut to_client, Message::Binary(wire::message(ch, &r.data)), gone_after).await {
                    break None;
                }
            }
            m = from_client.next() => {
                heard = Instant::now();
                let frame = match m {
                    Some(Ok(Message::Binary(b))) => input(&b),
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break None,
                    Some(Ok(_)) => Ok(None),
                };
                match frame {
                    // A guest gone is seen by the reader: its close ends the loop.
                    Ok(Some(f)) => {
                        let _ = guestc::write_request(&mut to_guest, &f).await;
                    }
                    Ok(None) => {}
                    Err(why) => break Some(SessionEnd::failed("invalid", why)),
                }
            }
            _ = beat.tick() => {
                if heard.elapsed() > gone_after
                    || !send(&mut to_client, Message::Ping(Vec::new()), gone_after).await
                {
                    break None;
                }
            }
        }
    };
    reader.abort();
    let Some(end) = end else {
        return Ended::ClientGone;
    };
    let last = serde_json::to_vec(&end).unwrap_or_default();
    let exit = Message::Binary(wire::message(channel::EXIT, &last));
    if send(&mut to_client, exit, gone_after).await {
        let close = Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "".into(),
        }));
        if send(&mut to_client, close, gone_after).await {
            // The closing handshake: the connection closes once the client closed it too (or
            // went silent), so what it still writes meanwhile never resets what it has not read.
            let closed = async {
                while let Some(Ok(m)) = from_client.next().await {
                    if matches!(m, Message::Close(_)) {
                        break;
                    }
                }
            };
            let _ = tokio::time::timeout(gone_after, closed).await;
        }
    }
    Ended::Command(end)
}

/// Sends a message, false when the client does not take it within `within`.
async fn send<Tx: Sink<Message> + Unpin>(tx: &mut Tx, m: Message, within: Duration) -> bool {
    matches!(tokio::time::timeout(within, tx.send(m)).await, Ok(Ok(())))
}

/// The guest frame a client's message asks for; `None` for one with nothing to do (an
/// unknown channel, a close of another stream than stdin).
fn input(m: &[u8]) -> Result<Option<Request>, String> {
    let Some((ch, payload)) = wire::parse(m) else {
        return Ok(None);
    };
    let op = |op: &str| Request {
        op: op.into(),
        ..Default::default()
    };
    Ok(match ch {
        channel::STDIN => Some(Request {
            data: payload.to_vec(),
            ..op("stdin")
        }),
        channel::RESIZE => {
            let r: Resize = serde_json::from_slice(payload).map_err(|e| format!("resize: {e}"))?;
            Some(Request {
                cols: r.cols,
                rows: r.rows,
                ..op("resize")
            })
        }
        channel::CLOSE if payload == [channel::STDIN] => Some(op("close_stdin")),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqyard_api::guest;
    use futures::channel::mpsc;
    use tokio::io::AsyncWriteExt;

    /// A session against a stand-in init: the client's side as two channels, the guest's as
    /// the other end of a pipe.
    struct Bench {
        client_tx: mpsc::UnboundedSender<Result<Message, axum::Error>>,
        client_rx: mpsc::UnboundedReceiver<Message>,
        guest: tokio::io::DuplexStream,
        ended: tokio::task::JoinHandle<Ended>,
    }

    fn bench(heartbeat: Duration) -> Bench {
        let (client_tx, rx) = mpsc::unbounded();
        let (tx, client_rx) = mpsc::unbounded();
        let (ours, guest) = tokio::io::duplex(1 << 16);
        let ended = tokio::spawn(pump(rx, tx, Box::new(ours), heartbeat));
        Bench {
            client_tx,
            client_rx,
            guest,
            ended,
        }
    }

    impl Bench {
        fn send(&self, ch: u8, payload: &[u8]) {
            self.client_tx
                .unbounded_send(Ok(Message::Binary(wire::message(ch, payload))))
                .unwrap();
        }

        async fn guest_says(&mut self, r: Response) {
            self.guest
                .write_all(&guest::encode_frame(&r).unwrap())
                .await
                .unwrap();
        }

        async fn guest_hears(&mut self) -> Request {
            guestc::read_frame(&mut self.guest).await.unwrap()
        }

        async fn client_hears(&mut self) -> Message {
            self.client_rx.next().await.unwrap()
        }
    }

    fn binary(m: Message) -> (u8, Vec<u8>) {
        match m {
            Message::Binary(b) => {
                let (c, p) = wire::parse(&b).unwrap();
                (c, p.to_vec())
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn messages_become_frames_and_back_then_the_exit() {
        let mut b = bench(Duration::from_secs(30));
        b.send(channel::STDIN, b"echo hi\n");
        b.send(channel::RESIZE, br#"{"cols":120,"rows":40}"#);
        b.send(channel::CLOSE, &[channel::STDIN]);
        let f = b.guest_hears().await;
        assert_eq!((f.op.as_str(), &f.data[..]), ("stdin", &b"echo hi\n"[..]));
        let f = b.guest_hears().await;
        assert_eq!((f.op.as_str(), f.cols, f.rows), ("resize", 120, 40));
        assert_eq!(b.guest_hears().await.op, "close_stdin");
        b.guest_says(Response::chunk("stdout", b"hi\n".to_vec()))
            .await;
        b.guest_says(Response::chunk("stderr", b"warn\n".to_vec()))
            .await;
        b.guest_says(Response::exit(3, false)).await;
        assert_eq!(
            binary(b.client_hears().await),
            (channel::STDOUT, b"hi\n".to_vec())
        );
        assert_eq!(
            binary(b.client_hears().await),
            (channel::STDERR, b"warn\n".to_vec())
        );
        let (ch, end) = binary(b.client_hears().await);
        assert_eq!(ch, channel::EXIT);
        let end: SessionEnd = serde_json::from_slice(&end).unwrap();
        assert_eq!((end.exit_code, end.code.as_str()), (Some(3), ""));
        assert!(matches!(b.client_hears().await, Message::Close(Some(c)) if c.code == 1000));
        b.client_tx
            .unbounded_send(Ok(Message::Close(None)))
            .unwrap();
        assert_eq!(
            b.ended.await.unwrap(),
            Ended::Command(SessionEnd {
                exit_code: Some(3),
                ..Default::default()
            })
        );
    }

    #[tokio::test]
    async fn the_end_waits_for_the_clients_close() {
        // Closing the connection under a client still writing (stdin it sent as the command
        // ended) resets it, and the reset can drop the exit it had not read yet (found by the
        // e2e suite): the server closes once the client did, as RFC 6455 has it.
        let mut b = bench(Duration::from_secs(30));
        b.guest_says(Response::exit(4, false)).await;
        assert_eq!(binary(b.client_hears().await).0, channel::EXIT);
        assert!(matches!(b.client_hears().await, Message::Close(_)));
        b.send(channel::STDIN, b"late input");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!b.ended.is_finished(), "closed before the client did");
        b.client_tx
            .unbounded_send(Ok(Message::Close(None)))
            .unwrap();
        let end = tokio::time::timeout(Duration::from_secs(5), b.ended)
            .await
            .expect("ends at the client's close")
            .unwrap();
        assert!(matches!(end, Ended::Command(e) if e.exit_code == Some(4)));
    }

    #[tokio::test]
    async fn the_clients_close_closes_the_guests_connection() {
        let mut b = bench(Duration::from_secs(30));
        b.client_tx
            .unbounded_send(Ok(Message::Close(None)))
            .unwrap();
        assert_eq!(b.ended.await.unwrap(), Ended::ClientGone);
        // The init reads the end of its connection: what ends the command.
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut b.guest, &mut rest)
            .await
            .unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn a_guest_gone_or_failing_is_the_last_message() {
        let mut b = bench(Duration::from_secs(30));
        drop(b.guest);
        let (ch, end) = binary(b.client_rx.next().await.unwrap());
        assert_eq!(ch, channel::EXIT);
        let end: SessionEnd = serde_json::from_slice(&end).unwrap();
        assert_eq!(
            end,
            SessionEnd::failed("not_running", "the machine went down during the command")
        );

        let mut b = bench(Duration::from_secs(30));
        b.guest_says(Response::error("empty command")).await;
        let (_, end) = binary(b.client_hears().await);
        let end: SessionEnd = serde_json::from_slice(&end).unwrap();
        assert_eq!(end, SessionEnd::failed("internal", "empty command"));

        // A resize that is not one ends the session as the client's mistake.
        let mut b = bench(Duration::from_secs(30));
        b.send(channel::RESIZE, b"80x24");
        let (_, end) = binary(b.client_hears().await);
        let end: SessionEnd = serde_json::from_slice(&end).unwrap();
        assert_eq!(end.code, "invalid");
        assert!(end.error.starts_with("resize: "), "{}", end.error);
    }

    #[tokio::test]
    async fn what_has_nothing_to_do_is_ignored() {
        let mut b = bench(Duration::from_secs(30));
        b.client_tx
            .unbounded_send(Ok(Message::Text("hello".into())))
            .unwrap();
        b.client_tx
            .unbounded_send(Ok(Message::Binary(vec![])))
            .unwrap();
        b.send(9, b"unknown channel");
        b.send(channel::CLOSE, &[channel::STDOUT]);
        b.send(channel::STDIN, b"x");
        let f = b.guest_hears().await;
        assert_eq!((f.op.as_str(), &f.data[..]), ("stdin", &b"x"[..]));
        b.guest_says(Response::chunk("progress", b"?".to_vec()))
            .await;
        b.guest_says(Response::exit(0, true)).await;
        let (ch, end) = binary(b.client_hears().await);
        assert_eq!(ch, channel::EXIT);
        let end: SessionEnd = serde_json::from_slice(&end).unwrap();
        assert!(end.timed_out);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_is_left() {
        // The client's side holds one message and reads none: a laptop asleep. Output keeps
        // coming; the session ends three heartbeats later instead of holding the machine.
        let (client_tx, rx) = mpsc::unbounded::<Result<Message, axum::Error>>();
        let (tx, _unread) = mpsc::channel::<Message>(0);
        let (ours, mut guest) = tokio::io::duplex(1 << 16);
        let ended = tokio::spawn(pump(rx, tx, Box::new(ours), Duration::from_secs(30)));
        tokio::spawn(async move {
            loop {
                let f = guest::encode_frame(&Response::chunk("stdout", vec![b'x'; 1024])).unwrap();
                if guest.write_all(&f).await.is_err() {
                    return;
                }
            }
        });
        let started = Instant::now();
        assert_eq!(ended.await.unwrap(), Ended::ClientGone);
        assert!(
            started.elapsed() <= Duration::from_secs(120),
            "{:?}",
            started.elapsed()
        );
        drop(client_tx);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_client_is_pinged_then_left() {
        let mut b = bench(Duration::from_secs(30));
        // A ping a beat; a pong (any message) keeps the session.
        assert!(matches!(b.client_hears().await, Message::Ping(_)));
        b.client_tx
            .unbounded_send(Ok(Message::Pong(Vec::new())))
            .unwrap();
        for _ in 0..3 {
            assert!(matches!(b.client_hears().await, Message::Ping(_)));
        }
        assert!(!b.ended.is_finished());
        // Silent past three beats since the pong: gone, with nothing more sent.
        assert_eq!(b.ended.await.unwrap(), Ended::ClientGone);
        assert!(b.client_rx.next().await.is_none());
    }
}
