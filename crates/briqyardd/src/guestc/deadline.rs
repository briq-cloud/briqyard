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
    pub fn from_sample(
        expires_at: u64,
        sample: &briqyard_api::execution::clock::ClockSample,
    ) -> Result<Self> {
        let expires = Duration::from_secs(expires_at);
        let remaining = expires
            .checked_sub(sample.uncertainty)
            .and_then(|upper| upper.checked_sub(sample.wall))
            .ok_or_else(|| anyhow!("execution authorization expired"))?;
        anyhow::ensure!(
            !remaining.is_zero()
                && remaining <= Duration::from_secs(briqyard_api::execution::MAX_COMMAND_SECONDS),
            "execution authorization outside freshness interval"
        );
        Ok(Self {
            expires: std::time::UNIX_EPOCH + expires,
            instant: tokio::time::Instant::from_std(sample.monotonic) + remaining,
        })
    }
    /// A fresh observation may only shorten the original monotonic deadline.
    pub fn refresh(&mut self) -> Result<()> {
        let sample = briqyard_api::execution::clock::ClockSample::read()
            .ok_or_else(|| anyhow!("qualified execution clock unavailable"))?;
        let upper = std::time::UNIX_EPOCH + sample.wall + sample.uncertainty;
        let remaining = self
            .expires
            .duration_since(upper)
            .map_err(|_| anyhow!("execution authorization expired"))?;
        self.instant = self
            .instant
            .min(tokio::time::Instant::from_std(sample.monotonic) + remaining);
        Ok(self.check()?)
    }
    #[cfg(test)]
    fn from_estimate(
        expires_at: u64,
        uncertainty: u64,
        wall: std::time::SystemTime,
        now: tokio::time::Instant,
    ) -> Result<Self> {
        let expires = std::time::UNIX_EPOCH
            .checked_add(Duration::from_secs(expires_at))
            .ok_or_else(|| anyhow!("invalid execution deadline"))?;
        let remaining = expires
            .duration_since(wall + Duration::from_secs(uncertainty))
            .map_err(|_| anyhow!("execution authorization expired"))?;
        if remaining.is_zero()
            || remaining > Duration::from_secs(briqyard_api::execution::MAX_COMMAND_SECONDS)
        {
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
        let sample = briqyard_api::execution::clock::ClockSample::read()
            .ok_or_else(|| anyhow!("qualified execution clock unavailable"))?;
        self.remaining_at(&sample, tokio::time::Instant::now())
    }
    fn remaining_at(
        &self,
        sample: &briqyard_api::execution::clock::ClockSample,
        now: tokio::time::Instant,
    ) -> Result<Duration> {
        let upper = std::time::UNIX_EPOCH + sample.wall + sample.uncertainty;
        let wall = self
            .expires
            .duration_since(upper)
            .map_err(|_| anyhow!("execution authorization expired"))?;
        let monotonic = self
            .instant
            .checked_duration_since(now)
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
    #[test]
    fn repeated_checks_subtract_uncertainty_once_without_extending_monotonic_time() {
        let sample = briqyard_api::execution::clock::ClockSample {
            wall: Duration::from_secs(1000),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_secs(2),
        };
        let deadline = CommandDeadline::from_sample(1010, &sample).unwrap();
        let origin = tokio::time::Instant::from_std(sample.monotonic);
        assert_eq!(
            deadline.remaining_at(&sample, origin).unwrap(),
            Duration::from_secs(8)
        );
        let later = briqyard_api::execution::clock::ClockSample {
            wall: Duration::from_secs(1001),
            monotonic: sample.monotonic + Duration::from_secs(1),
            uncertainty: Duration::from_secs(1),
        };
        assert_eq!(
            deadline
                .remaining_at(&later, origin + Duration::from_secs(1))
                .unwrap(),
            Duration::from_secs(7)
        );
        assert!(deadline
            .remaining_at(&later, origin + Duration::from_secs(8))
            .is_err());
    }
    #[test]
    fn qualified_sample_anchors_both_clocks_and_keeps_fractional_deadline() {
        let sample = briqyard_api::execution::clock::ClockSample {
            wall: Duration::from_millis(1_010_900),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_millis(50),
        };
        let deadline = CommandDeadline::from_sample(1011, &sample).unwrap();
        assert_eq!(
            deadline.instant.into_std() - sample.monotonic,
            Duration::from_millis(50)
        );
        assert!(CommandDeadline::from_sample(1010, &sample).is_err());
        assert!(CommandDeadline::from_sample(1072, &sample).is_err());
    }
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
