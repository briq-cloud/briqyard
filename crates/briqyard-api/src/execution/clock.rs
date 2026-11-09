//! Read-only kernel clock qualification for host authority transitions.
use super::Clock;
use std::time::{Duration, Instant};

pub struct QualifiedClock {
    pub interval: Clock,
    pub valid_until: Instant,
}
pub trait ClockSource: Send + Sync {
    fn qualified(&self) -> Option<QualifiedClock>;
}
/// No fallback to an unqualified wall clock on unsupported systems or clock loss.
pub struct KernelClock;
impl ClockSource for KernelClock {
    fn qualified(&self) -> Option<QualifiedClock> {
        let sample = ClockSample::read()?;
        Some(QualifiedClock {
            interval: sample.interval()?,
            valid_until: sample.monotonic.checked_add(Duration::from_secs(1))?,
        })
    }
}
/// Wall time and monotonic anchor from the same bracketed kernel observation.
#[derive(Clone)]
pub struct ClockSample {
    pub wall: Duration,
    pub monotonic: Instant,
    pub uncertainty: Duration,
}
impl ClockSample {
    pub fn interval(&self) -> Option<Clock> {
        // Flooring wall time introduces up to one second of additional error.
        let uncertainty = self
            .uncertainty
            .checked_add(Duration::from_nanos(self.wall.subsec_nanos().into()))?;
        let seconds = uncertainty
            .as_secs()
            .checked_add(u64::from(uncertainty.subsec_nanos() > 0))?;
        (seconds <= 5).then_some(Clock {
            now: self.wall.as_secs(),
            uncertainty: seconds,
        })
    }
    pub fn lower_ms(&self) -> Option<u64> {
        self.wall
            .checked_sub(self.uncertainty)?
            .as_millis()
            .try_into()
            .ok()
    }
    pub fn upper_ms(&self) -> Option<u64> {
        self.wall
            .checked_add(self.uncertainty)?
            .as_millis()
            .checked_add(1)?
            .try_into()
            .ok()
    }
    #[cfg(target_os = "linux")]
    pub fn read() -> Option<Self> {
        use nix::libc;
        let began = Instant::now();
        // modes=0 observes only: this never adjusts the system clock.
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        let state = unsafe { libc::adjtimex(&mut tx) };
        let ended = Instant::now();
        if state != libc::TIME_OK || tx.status & (libc::STA_UNSYNC | libc::STA_CLOCKERR) != 0 {
            return None;
        }
        let sample = Self::from_reading(
            tx.time.tv_sec,
            tx.time.tv_usec,
            tx.offset,
            tx.maxerror,
            tx.esterror,
            tx.status & libc::STA_NANO != 0,
            began,
            ended.checked_duration_since(began)?,
        )?;
        // Retain the first qualified anchor for the entire process lifetime. A later wall step
        // cannot manufacture fresh authority merely because NTP status cleared.
        static ANCHOR: std::sync::Mutex<Option<ClockSample>> = std::sync::Mutex::new(None);
        let mut anchor = ANCHOR.lock().ok()?;
        if let Some(previous) = anchor.as_ref() {
            if !sample.follows(previous) {
                return None;
            }
        }
        // Never reset after an accepted sample: pairwise overlapping error
        // intervals otherwise permit unbounded accumulation of small wall steps.
        anchor.get_or_insert_with(|| sample.clone());
        Some(sample)
    }
    #[cfg(any(target_os = "linux", test))]
    fn follows(&self, previous: &Self) -> bool {
        let Some(elapsed) = self.monotonic.checked_duration_since(previous.monotonic) else {
            return false;
        };
        let Some(expected) = previous.wall.checked_add(elapsed) else {
            return false;
        };
        let difference = self.wall.abs_diff(expected);
        previous
            .uncertainty
            .checked_add(self.uncertainty)
            .is_some_and(|bound| difference <= bound)
    }
    #[cfg(any(target_os = "linux", test))]
    #[allow(clippy::too_many_arguments)]
    fn from_reading(
        seconds: i64,
        fraction: i64,
        offset: i64,
        maxerror: i64,
        esterror: i64,
        nanos: bool,
        began: Instant,
        bracket: Duration,
    ) -> Option<Self> {
        let unit = if nanos { 1 } else { 1_000 };
        let fraction = u64::try_from(fraction).ok()?.checked_mul(unit)?;
        if fraction >= 1_000_000_000 {
            return None;
        }
        let wall = Duration::from_secs(seconds.try_into().ok()?)
            .checked_add(Duration::from_nanos(fraction))?;
        // maxerror and esterror remain microseconds with STA_NANO.
        let error = u64::try_from(maxerror)
            .ok()?
            .checked_add(u64::try_from(esterror).ok()?)?
            .checked_mul(1_000)?;
        let offset = u64::try_from(offset.checked_abs()?)
            .ok()?
            .checked_mul(unit)?;
        let uncertainty = Duration::from_nanos(error.checked_add(offset)?.checked_add(unit)?)
            .checked_add(bracket)?
            .checked_add(Duration::from_secs(1))?;
        if uncertainty > Duration::from_secs(5) {
            return None;
        }
        Some(Self {
            wall,
            monotonic: began,
            uncertainty,
        })
    }
    #[cfg(not(target_os = "linux"))]
    pub fn read() -> Option<Self> {
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forward_and_backward_steps_do_not_replace_monotonic_anchor() {
        let first = ClockSample {
            wall: Duration::from_secs(100),
            monotonic: Instant::now(),
            uncertainty: Duration::from_millis(100),
        };
        let mut next = first.clone();
        next.monotonic += Duration::from_secs(1);
        next.wall += Duration::from_secs(1);
        assert!(next.follows(&first));
        next.wall += Duration::from_secs(10);
        assert!(!next.follows(&first));
        next.wall = Duration::from_secs(90);
        assert!(!next.follows(&first));
    }
    #[test]
    fn repeated_subthreshold_steps_cannot_accumulate_authority() {
        let anchor = ClockSample {
            wall: Duration::from_secs(100),
            monotonic: Instant::now(),
            uncertainty: Duration::from_secs(1),
        };
        let mut previous = anchor.clone();
        for step in 1..=60 {
            let sample = ClockSample {
                wall: anchor.wall + Duration::from_secs(step * 2),
                monotonic: anchor.monotonic + Duration::from_secs(step),
                uncertainty: Duration::from_secs(1),
            };
            // Every +1s step passes the flawed moving-anchor predicate.
            assert!(sample.follows(&previous));
            assert_eq!(sample.follows(&anchor), step <= 2);
            if sample.follows(&anchor) {
                // Its lower bound cannot outrun the original upper bound
                // advanced by monotonic elapsed time.
                assert!(sample.lower_ms().unwrap() <= anchor.upper_ms().unwrap() + step * 1000);
            }
            previous = sample;
        }
    }
    #[test]
    fn interval_rounds_outward_and_refuses_excess_error() {
        let mut sample = ClockSample {
            wall: Duration::from_millis(10_900),
            monotonic: Instant::now(),
            uncertainty: Duration::from_millis(200),
        };
        assert_eq!(sample.interval().unwrap().uncertainty, 2);
        assert_eq!(sample.lower_ms(), Some(10_700));
        assert_eq!(sample.upper_ms(), Some(11_101));
        sample.uncertainty = Duration::from_secs(5);
        assert!(sample.interval().is_none());
    }
    #[test]
    fn units_negatives_overflow_and_error_ceiling_fail_closed() {
        let at = Instant::now();
        let read = |nano, max, offset| {
            ClockSample::from_reading(100, 0, offset, max, 1000, nano, at, Duration::ZERO)
        };
        let micro = read(false, 1000, -1000).unwrap();
        let nano = read(true, 1000, -1_000_000).unwrap();
        assert_eq!(
            micro.uncertainty - nano.uncertainty,
            Duration::from_nanos(999)
        );
        for (nano, max, offset) in [
            (true, -1, 0),
            (false, i64::MAX, 0),
            (true, 1, i64::MIN),
            (false, 5_000_000, 0),
        ] {
            assert!(read(nano, max, offset).is_none());
        }
        assert!(ClockSample::from_reading(-1, 0, 0, 0, 0, true, at, Duration::ZERO).is_none());
        assert!(
            ClockSample::from_reading(100, 1_000_000_000, 0, 0, 0, true, at, Duration::ZERO)
                .is_none()
        );
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_clock_fails_closed() {
        assert!(KernelClock.qualified().is_none());
    }
}
