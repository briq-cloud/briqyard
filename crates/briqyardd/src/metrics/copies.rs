//! Bounded labels and histogram storage for ADR 0092.
use super::*;
use std::fmt::Write;
const BOUNDS: [f64; 8] = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1., 30.];
#[derive(Clone, Default)]
pub struct Copies {
    counts: BTreeMap<(&'static str, String), u64>,
    buckets: [u64; 8],
    held: u64,
    seconds: f64,
}
impl Copies {
    pub fn record(&mut self, op: &'static str, consistency: &str, held: Option<f64>) {
        *self.counts.entry((op, consistency.into())).or_default() += 1;
        self.hold(held);
    }
    pub fn hold(&mut self, held: Option<f64>) {
        if let Some(seconds) = held {
            self.held += 1;
            self.seconds += seconds;
            for (i, bound) in BOUNDS.iter().enumerate() {
                if seconds <= *bound {
                    self.buckets[i] += 1;
                }
            }
        }
    }
    pub fn render(&self, out: &mut String) {
        out.push_str("# HELP briqyard_copies_total Disk copies by achieved consistency.\n# TYPE briqyard_copies_total counter\n");
        for ((op, c), n) in &self.counts {
            let _ = writeln!(
                out,
                "briqyard_copies_total{{operation=\"{op}\",consistency=\"{c}\"}} {n}"
            );
        }
        out.push_str("# HELP briqyard_fs_freeze_seconds Host-observed freeze hold through thaw acknowledgment.\n# TYPE briqyard_fs_freeze_seconds histogram\n");
        for (bound, n) in BOUNDS.iter().zip(self.buckets) {
            let _ = writeln!(
                out,
                "briqyard_fs_freeze_seconds_bucket{{le=\"{bound}\"}} {n}"
            );
        }
        let _ = writeln!(out, "briqyard_fs_freeze_seconds_bucket{{le=\"+Inf\"}} {}\nbriqyard_fs_freeze_seconds_count {}\nbriqyard_fs_freeze_seconds_sum {}", self.held, self.held, self.seconds);
    }
}
