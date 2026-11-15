//! Append-only upgrade observations. An unmatched start is ambiguous, never success.
use briqyard_api::UpgradeTimingEvent;
use chrono::Utc;
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

pub(crate) struct Timing {
    file: File,
    started: Instant,
    phase: &'static str,
    host: String,
    attempt: String,
}

fn directory(root: &Path, host: &str) -> PathBuf {
    let key: String = host.bytes().map(|b| format!("{b:02x}")).collect();
    root.join("upgrade-timings").join(key)
}

impl Timing {
    pub(crate) fn new(root: &Path, host: &str, from: &str, release: &str) -> std::io::Result<Self> {
        let dir = directory(root, host);
        fs::create_dir_all(&dir)?;
        let attempt = format!(
            "{}-{:016x}",
            Utc::now().format("%Y%m%dT%H%M%S%.9f"),
            rand::random::<u64>()
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(format!("{attempt}.jsonl")))?;
        let requested = release
            .rsplit('/')
            .next()
            .unwrap_or(release)
            .trim_start_matches('v');
        let requested = if !requested.is_empty()
            && requested.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        {
            requested
        } else {
            "custom"
        };
        writeln!(
            file,
            "{}",
            json!({"schemaVersion":1,"attempt":attempt,"host":host,"fromVersion":from,"release":requested,"event":"attempt","at":Utc::now()})
        )?;
        file.sync_all()?;
        let pointer = dir.join(format!("{attempt}.pointer"));
        let mut latest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pointer)?;
        write!(latest, "{attempt}.jsonl")?;
        latest.sync_all()?;
        fs::rename(pointer, dir.join("latest"))?;
        File::open(&dir)?.sync_all()?;
        File::open(root.join("upgrade-timings"))?.sync_all()?;
        File::open(root)?.sync_all()?;
        Ok(Self {
            file,
            started: Instant::now(),
            phase: "prepare",
            host: host.into(),
            attempt,
        })
    }

    fn event(&mut self, outcome: &str, elapsed_ms: Option<u64>) {
        let value = json!({"event":"phase","phase":self.phase,"outcome":outcome,"elapsedMs":elapsed_ms,"at":Utc::now()});
        // Once dispatch is possible, telemetry failure must never change lifecycle or trigger replay.
        if writeln!(self.file, "{value}")
            .and_then(|_| self.file.sync_all())
            .is_err()
        {
            tracing::warn!(
                host = self.host,
                attempt = self.attempt,
                phase = self.phase,
                "upgrade timing persistence failed"
            );
        }
        tracing::info!(
            host = self.host,
            attempt = self.attempt,
            phase = self.phase,
            outcome,
            elapsed_ms,
            "upgrade phase"
        );
    }

    pub(crate) fn start(&mut self, phase: &'static str) {
        self.start_at(phase, Instant::now());
    }

    fn start_at(&mut self, phase: &'static str, now: Instant) {
        self.phase = phase;
        self.started = now;
        self.event("running", None);
    }

    pub(crate) fn end(&mut self, success: bool) {
        self.end_at(success, Instant::now());
    }

    fn end_at(&mut self, success: bool, now: Instant) {
        self.event(
            if success { "succeeded" } else { "failed" },
            Some(milliseconds(now.duration_since(self.started))),
        );
    }
}

fn milliseconds(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// Latest attempt only; every earlier file remains available to an operator.
pub(crate) fn latest(root: &Path, host: &str) -> std::io::Result<Vec<UpgradeTimingEvent>> {
    let dir = directory(root, host);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let name = fs::read_to_string(dir.join("latest"))?;
    if name.contains('/') || !name.ends_with(".jsonl") {
        return Err(std::io::Error::other("invalid timing pointer"));
    }
    let path = dir.join(name);
    let data = fs::read(path)?;
    if data.len() > 65536 {
        return Err(std::io::Error::other("timing record too large"));
    }
    // A torn final append is unknown, not evidence of completion.
    Ok(data
        .split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duration_is_monotonic_arithmetic() {
        assert_eq!(
            milliseconds(std::time::Duration::from_micros(1234567)),
            1234
        );
    }
    #[test]
    fn attempts_preserve_prior_failure_and_unfinished_start() {
        let dir = std::env::temp_dir().join(format!("upgrade-timing-{}", rand::random::<u64>()));
        let mut first = Timing::new(
            &dir,
            "../host",
            "old",
            "https://example.invalid/releases/download/v0.2.12",
        )
        .unwrap();
        let clock = Instant::now();
        first.start_at("prepare", clock);
        first.end_at(false, clock + std::time::Duration::from_millis(1234));
        let failed = serde_json::to_value(latest(&dir, "../host").unwrap()).unwrap();
        assert_eq!(failed[0]["release"], "0.2.12");
        assert_eq!(failed[2]["elapsedMs"], 1234);
        assert_eq!(failed[2]["outcome"], "failed");
        let mut next = Timing::new(&dir, "../host", "old", "new").unwrap();
        next.start("activation");
        let events = serde_json::to_value(latest(&dir, "../host").unwrap()).unwrap();
        assert_eq!(events[1]["outcome"], "running");
        assert!(events[1]["elapsedMs"].is_null());
        assert_eq!(
            fs::read_dir(directory(&dir, "../host"))
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "jsonl"))
                .count(),
            2
        );
        // A torn end cannot turn a running phase into success.
        writeln!(next.file, "{{partial").unwrap();
        assert_eq!(latest(&dir, "../host").unwrap().len(), 2);
        // An unwritable timing sink after creation does not change lifecycle control flow.
        next.file = File::open(directory(&dir, "../host").join("latest")).unwrap();
        next.end_at(false, next.started + std::time::Duration::from_secs(1));
        assert_eq!(latest(&dir, "../host").unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
}
