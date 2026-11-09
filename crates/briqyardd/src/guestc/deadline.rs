use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// A fixed wall-clock expiry narrowed by uncertainty, mapped once to monotonic time.
/// Both clocks are checked at each guest read/write poll; verification or fsync time
/// never starts a new authorization interval.
#[derive(Clone)]
pub struct CommandDeadline {
    expires: std::time::SystemTime,
    pub(crate) instant: tokio::time::Instant,
}
impl CommandDeadline {
    pub fn new(expires_at: u64, uncertainty: u64) -> Result<Self> {
        let instant = tokio::time::Instant::now();
        let wall = std::time::SystemTime::now();
        Self::from_estimate(expires_at, uncertainty, wall, instant)
    }
    fn from_estimate(
        expires_at: u64,
        uncertainty: u64,
        wall: std::time::SystemTime,
        now: tokio::time::Instant,
    ) -> Result<Self> {
        let expires = std::time::UNIX_EPOCH
            .checked_add(Duration::from_secs(expires_at))
            .and_then(|t| t.checked_sub(Duration::from_secs(uncertainty)))
            .ok_or_else(|| anyhow!("invalid execution deadline"))?;
        let remaining = expires
            .duration_since(wall)
            .map_err(|_| anyhow!("execution authorization expired"))?;
        if remaining.is_zero() || remaining > Duration::from_secs(60) {
            return Err(anyhow!(
                "execution authorization outside freshness interval"
            ));
        }
        Ok(Self {
            expires,
            instant: now + remaining,
        })
    }
    pub fn remaining(&self) -> Result<Duration> {
        let wall = self
            .expires
            .duration_since(std::time::SystemTime::now())
            .map_err(|_| anyhow!("execution authorization expired"))?;
        let monotonic = self
            .instant
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| anyhow!("execution authorization expired"))?;
        let remaining = wall.min(monotonic);
        if remaining.is_zero() {
            return Err(anyhow!("execution authorization expired"));
        }
        Ok(remaining)
    }
    pub fn check(&self) -> std::io::Result<()> {
        self.remaining().map(|_| ()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "execution authorization expired",
            )
        })
    }
}
pub(super) struct ExpiringConnection<T> {
    pub(super) conn: T,
    pub(super) deadline: CommandDeadline,
}
impl<T: AsyncRead + Unpin> AsyncRead for ExpiringConnection<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Err(e) = self.deadline.check() {
            return std::task::Poll::Ready(Err(e));
        }
        std::pin::Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ExpiringConnection<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if let Err(e) = self.deadline.check() {
            return std::task::Poll::Ready(Err(e));
        }
        std::pin::Pin::new(&mut self.conn).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Err(e) = self.deadline.check() {
            return std::task::Poll::Ready(Err(e));
        }
        std::pin::Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guestc::write_request;
    use briqyard_api::guest::Request;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn scoped_fractional_expiry_and_expired_write_never_extend_authority() {
        let instant = tokio::time::Instant::now();
        let wall = std::time::UNIX_EPOCH + Duration::from_millis(1_010_900);
        let precise = CommandDeadline::from_estimate(1011, 0, wall, instant).unwrap();
        assert_eq!(precise.instant - instant, Duration::from_millis(100));
        let (writer, mut peer) = tokio::io::duplex(4096);
        let expired = CommandDeadline {
            expires: std::time::SystemTime::now() - Duration::from_millis(1),
            instant: tokio::time::Instant::now() - Duration::from_millis(1),
        };
        let mut writer = ExpiringConnection {
            conn: writer,
            deadline: expired.clone(),
        };
        let _ = tokio::time::timeout_at(
            expired.instant,
            write_request(&mut writer, &Request::default()),
        )
        .await;
        drop(writer);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "an expired command must not write a guest frame"
        );
    }
}
