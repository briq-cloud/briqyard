//! A machine's serial console (ADR 0021): `console.log` in its run dir, stamped line by line
//! by the daemon and rotated by size while the machine runs. The previous file is kept as
//! `console.<start>.log`, named after the offset it starts at in the whole console: a cursor
//! is an offset in the whole console, so a read goes across both files, and what was rotated
//! away twice is gone. A follower (ADR 0025) waits on the console's `grown` notifier, which
//! the writer wakes after each line.
//!
//! One file holds both views (ADR 0115). A line is `<ts> <text>` for the app's, as it always
//! was, and `<ts>! <text>` for the runtime's: a line written before the views existed has
//! no mark and reads as the app's, so a console that spans an upgrade stays whole.

use briqyard_api::LogView;
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

const CURRENT: &str = "console.log";

/// Ends the timestamp of a runtime line (an RFC 3339 time never ends with it).
const RUNTIME_MARK: char = '!';

/// Starts what the guest's init prints (`briqyard-init`'s `console_line`).
const INIT_PREFIX: &str = "[briqyard] ";

/// The view of a line the guest wrote to its serial console, which the kernel, the init and
/// the customer's program all print to. The kernel stamps its own lines with the time since
/// boot (`printk.time=1`, in the boot arguments) and the init starts its own with
/// `[briqyard] `: anything else is the program's.
pub fn serial_view(line: &[u8]) -> LogView {
    if line.starts_with(INIT_PREFIX.as_bytes()) || kernel_stamped(line) {
        LogView::Runtime
    } else {
        LogView::App
    }
}

/// `[    1.234567] `: the kernel's time since boot.
fn kernel_stamped(line: &[u8]) -> bool {
    let Some(rest) = line.strip_prefix(b"[") else {
        return false;
    };
    let rest = rest.trim_ascii_start();
    let secs = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let Some(rest) = rest[secs..].strip_prefix(b".") else {
        return false;
    };
    let micros = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    secs > 0 && micros > 0 && rest[micros..].starts_with(b"] ")
}

/// The view a stored line belongs to, its timestamp and the text, from the line as written
/// (without its newline). `None` when it has no timestamp.
pub fn unstamp(stored: &str) -> Option<(LogView, &str, &str)> {
    let (stamp, text) = stored.split_once(' ')?;
    Some(match stamp.strip_suffix(RUNTIME_MARK) {
        Some(ts) => (LogView::Runtime, ts, text),
        None => (LogView::App, stamp, text),
    })
}

/// Held to rename the files (a rotation) and to find and open them (a read), so a reader never
/// takes one file's start for another's. One for the daemon: a rotation is a rename, an
/// unlink and an open.
static LAYOUT: RwLock<()> = RwLock::new(());

/// The notifier of each console a writer or a follower holds, by its dir.
static GROWN: Mutex<BTreeMap<PathBuf, Weak<Notify>>> = Mutex::new(BTreeMap::new());

/// What the console in `dir` wakes after each line it is given: the same for the writer and
/// every follower while one of them holds it.
pub fn grown(dir: &Path) -> Arc<Notify> {
    let mut all = GROWN.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|_, n| n.strong_count() > 0);
    if let Some(n) = all.get(dir).and_then(Weak::upgrade) {
        return n;
    }
    let n = Arc::new(Notify::new());
    all.insert(dir.to_path_buf(), Arc::downgrade(&n));
    n
}

/// The previous files in `dir`, by the offset each starts at; a missing dir has none.
fn previous(dir: &Path) -> std::io::Result<Vec<(u64, PathBuf)>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for e in rd {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let start = name
            .strip_prefix("console.")
            .and_then(|r| r.strip_suffix(".log"))
            .and_then(|n| n.parse::<u64>().ok());
        if let Some(start) = start {
            out.push((start, e.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// The console's files as they are now, opened under the layout lock.
struct Files {
    /// The previous file: where it starts, its length, the file.
    prev: Option<(u64, u64, std::fs::File)>,
    /// The current file and where it starts.
    current: Option<std::fs::File>,
    start: u64,
}

fn open_files(dir: &Path) -> std::io::Result<Files> {
    let _g = LAYOUT.read().unwrap_or_else(|e| e.into_inner());
    let prev = match previous(dir)?.pop() {
        Some((start, p)) => {
            let f = std::fs::File::open(p)?;
            Some((start, f.metadata()?.len(), f))
        }
        None => None,
    };
    let current = match std::fs::File::open(dir.join(CURRENT)) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let start = prev.as_ref().map_or(0, |(s, len, _)| s + len);
    Ok(Files {
        prev,
        current,
        start,
    })
}

/// Where the console ends now: the offset the next line will be written at.
pub fn end(dir: &Path) -> std::io::Result<u64> {
    let f = open_files(dir)?;
    let len = match &f.current {
        Some(c) => c.metadata()?.len(),
        None => 0,
    };
    Ok(f.start + len)
}

/// The console from `from` (an offset in the whole console) to its end as it is now: where
/// it reads from (`from`, or the oldest offset kept when `from` was rotated away) and the
/// bytes. `None` when the machine has no console yet.
pub fn read_from(dir: &Path, from: u64) -> std::io::Result<Option<(u64, impl BufRead)>> {
    let f = open_files(dir)?;
    if f.prev.is_none() && f.current.is_none() {
        return Ok(None);
    }
    let oldest = f.prev.as_ref().map_or(0, |(s, _, _)| *s);
    let at = from.max(oldest);
    let mut bytes: Box<dyn Read + Send> = Box::new(std::io::empty());
    if let Some((s, len, mut p)) = f.prev {
        if at < s + len {
            p.seek(SeekFrom::Start(at - s))?;
            bytes = Box::new(p.take(len - (at - s)));
        }
    }
    if let Some(mut c) = f.current {
        c.seek(SeekFrom::Start(at.saturating_sub(f.start)))?;
        bytes = Box::new(bytes.chain(c));
    }
    Ok(Some((
        at,
        std::io::BufReader::with_capacity(64 << 10, bytes),
    )))
}

/// The daemon's end of a console: lines written whole, the file rotated once it passes
/// `max` bytes. Shared by the tasks that copy the process's output, behind one lock: a
/// rotation happens between two lines, never inside one, and none is lost.
pub struct Writer {
    dir: PathBuf,
    max: u64,
    grown: Arc<Notify>,
    file: tokio::fs::File,
    /// The current file's length.
    len: u64,
    /// Where the current file starts in the console.
    start: u64,
}

fn open_current(dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(dir.join(CURRENT))
}

impl Writer {
    /// Opens the console for appending; one already past `max` is rotated first.
    pub async fn open(dir: &Path, max: u64) -> std::io::Result<Self> {
        let file = open_current(dir)?;
        let len = file.metadata()?.len();
        let start = open_files(dir)?.start;
        let mut w = Self {
            dir: dir.to_path_buf(),
            max,
            grown: grown(dir),
            file: tokio::fs::File::from_std(file),
            len,
            start,
        };
        if w.len >= w.max {
            w.rotate().await?;
        }
        Ok(w)
    }

    /// Writes one line as `<ts> <line>\n` (`<ts>! <line>\n` for the runtime's), then rotates
    /// when the file passed the size. The line is in the file when this returns (a tokio file
    /// hands a write to a thread, and only a flush waits for it), and the followers are woken.
    pub async fn line(&mut self, ts: &str, view: LogView, line: &[u8]) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(ts.len() + line.len() + 3);
        buf.extend_from_slice(ts.as_bytes());
        if view == LogView::Runtime {
            buf.push(RUNTIME_MARK as u8);
        }
        buf.push(b' ');
        buf.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            buf.push(b'\n');
        }
        self.file.write_all(&buf).await?;
        self.file.flush().await?;
        self.len += buf.len() as u64;
        if self.len >= self.max {
            self.rotate().await?;
        }
        self.grown.notify_waiters();
        Ok(())
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush().await
    }

    /// Renames the current file after where it starts, removes the older ones and opens a
    /// new current file. Written out first: the renamed file's length is where the new one
    /// starts.
    async fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush().await?;
        let file = {
            let _g = LAYOUT.write().unwrap_or_else(|e| e.into_inner());
            let old = previous(&self.dir)?;
            std::fs::rename(
                self.dir.join(CURRENT),
                self.dir.join(format!("console.{}.log", self.start)),
            )?;
            for (_, p) in old {
                let _ = std::fs::remove_file(p);
            }
            open_current(&self.dir)?
        };
        self.file = tokio::fs::File::from_std(file);
        self.start += self.len;
        self.len = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every line from `from`, and where the read ended.
    fn lines(dir: &Path, from: u64) -> (Vec<String>, u64) {
        let Some((mut pos, r)) = read_from(dir, from).unwrap() else {
            return (vec![], from);
        };
        let mut out = vec![];
        for l in r.lines() {
            let l = l.unwrap();
            pos += l.len() as u64 + 1;
            out.push(l.split_once(' ').unwrap().1.to_string());
        }
        (out, pos)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn a_console_past_its_size_is_rotated_and_read_across() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(read_from(d, 0).unwrap().is_none(), "no console yet");
        // Each line is 9 bytes, "ts lineN\n": line N starts at 9 N.
        let mut w = Writer::open(d, 25).await.unwrap();
        for i in 0..3 {
            w.line("ts", LogView::App, format!("line{i}").as_bytes())
                .await
                .unwrap();
        }
        w.flush().await.unwrap();
        // The third line took the file to 27 bytes: rotated, the next starts at 27.
        assert_eq!(names(d), vec!["console.0.log", "console.log"]);
        assert_eq!(end(d).unwrap(), 27);
        let (l, next) = lines(d, 0);
        assert_eq!(
            (l, next),
            (vec!["line0".into(), "line1".into(), "line2".into()], 27)
        );
        w.line("ts", LogView::App, b"line3").await.unwrap();
        w.flush().await.unwrap();
        // A cursor in the previous file reads on into the current one.
        assert_eq!(lines(d, 18), (vec!["line2".into(), "line3".into()], 36));
        assert_eq!(lines(d, 27), (vec!["line3".into()], 36));
        for i in 4..6 {
            w.line("ts", LogView::App, format!("line{i}").as_bytes())
                .await
                .unwrap();
        }
        w.flush().await.unwrap();
        // A second rotation: one previous file kept, a cursor in the one before reads on from
        // the oldest line kept.
        assert_eq!(names(d), vec!["console.27.log", "console.log"]);
        assert_eq!(
            lines(d, 0),
            (vec!["line3".into(), "line4".into(), "line5".into()], 54)
        );
        // Past the end: nothing, the cursor kept.
        assert_eq!(lines(d, 54), (vec![], 54));
        assert_eq!(lines(d, 99), (vec![], 99));
        // A new writer (a new boot) goes on where the console ends.
        drop(w);
        let mut w = Writer::open(d, 25).await.unwrap();
        w.line("ts", LogView::App, b"line6").await.unwrap();
        w.flush().await.unwrap();
        assert_eq!(lines(d, 54), (vec!["line6".into()], 63));
    }

    #[tokio::test]
    async fn a_line_is_in_the_file_and_wakes_the_followers_once_written() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let follower = grown(d);
        let mut w = Writer::open(d, 1 << 20).await.unwrap();
        assert!(Arc::ptr_eq(&follower, &w.grown), "one notifier per console");
        {
            let woken = follower.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            w.line("ts", LogView::App, b"one").await.unwrap();
            // No flush: the line is there for a page or a follower as soon as it is written.
            assert_eq!(lines(d, 0), (vec!["one".into()], 7));
            tokio::time::timeout(std::time::Duration::from_secs(1), woken)
                .await
                .expect("the follower is woken");
        }
        // Held by nobody, a console's notifier goes.
        drop((w, follower));
        let _ = grown(&d.join("other"));
        assert!(!GROWN.lock().unwrap().contains_key(d));
    }

    #[tokio::test]
    async fn a_console_already_past_its_size_is_rotated_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join(CURRENT), "ts old\n".repeat(10)).unwrap();
        let w = Writer::open(d, 50).await.unwrap();
        assert_eq!(names(d), vec!["console.0.log", "console.log"]);
        assert_eq!((w.start, w.len), (70, 0));
        assert_eq!(lines(d, 63), (vec!["old".into()], 70));
    }

    #[tokio::test]
    async fn rotating_while_two_tasks_write_loses_no_line() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_path_buf();
        // Small enough that the file rotates every few lines, large enough that two rotations
        // never pass between one read of the files and the next.
        let w = std::sync::Arc::new(tokio::sync::Mutex::new(
            Writer::open(&d, 400).await.unwrap(),
        ));
        let mut tasks = vec![];
        for t in 0..2 {
            let w = w.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..500 {
                    w.lock()
                        .await
                        .line("ts", LogView::App, format!("{t}-{i:03}").as_bytes())
                        .await
                        .unwrap();
                    tokio::task::yield_now().await;
                }
            }));
        }
        // A reader follows from a cursor while the writers rotate under it.
        let mut seen = vec![];
        let mut cursor = 0;
        loop {
            let done = tasks.iter().all(|t| t.is_finished());
            w.lock().await.flush().await.unwrap();
            let (l, next) = lines(&d, cursor);
            assert!(next >= cursor);
            seen.extend(l);
            cursor = next;
            if done {
                break;
            }
            tokio::task::yield_now().await;
        }
        for t in tasks {
            t.await.unwrap();
        }
        w.lock().await.flush().await.unwrap();
        let (l, _) = lines(&d, cursor);
        seen.extend(l);
        for t in 0..2 {
            let mine: Vec<&String> = seen
                .iter()
                .filter(|l| l.starts_with(&format!("{t}-")))
                .collect();
            let want: Vec<String> = (0..500).map(|i| format!("{t}-{i:03}")).collect();
            assert_eq!(mine, want.iter().collect::<Vec<_>>(), "task {t}");
        }
    }

    #[test]
    fn the_guests_serial_lines_are_split_by_who_printed_them() {
        for runtime in [
            "[briqyard] started pid=7 /app --token x",
            "[briqyard] exit code=1 oom=false requested=false",
            "[    0.000000] Linux version 6.1.102",
            "[   12.345678] Kernel panic - not syncing: Attempted to kill init!",
            "[123456.789012] reboot: Restarting system",
        ] {
            assert_eq!(
                serial_view(runtime.as_bytes()),
                LogView::Runtime,
                "{runtime}"
            );
        }
        for app in [
            "listening on :8080",
            "",
            "[briqyard]",
            " [briqyard] indented",
            "[INFO] 12.5 ready",
            "[ 12 ] not a time",
            "[12.] no micros",
            "[.5] no seconds",
            "[1.5]no space",
            "[2026-11-05T20:15:53Z] request",
        ] {
            assert_eq!(serial_view(app.as_bytes()), LogView::App, "{app}");
        }
    }

    #[tokio::test]
    async fn a_runtime_line_is_marked_and_a_line_without_the_mark_is_the_apps() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // A console from before the views: unmarked lines.
        std::fs::write(d.join(CURRENT), "2026-10-21T10:00:00.000000Z old\n").unwrap();
        let mut w = Writer::open(d, 1 << 20).await.unwrap();
        w.line("2026-10-21T10:00:01.000000Z", LogView::App, b"app\n")
            .await
            .unwrap();
        w.line("2026-10-21T10:00:02.000000Z", LogView::Runtime, b"run")
            .await
            .unwrap();
        w.flush().await.unwrap();
        let text = std::fs::read_to_string(d.join(CURRENT)).unwrap();
        assert_eq!(
            text,
            "2026-10-21T10:00:00.000000Z old\n\
             2026-10-21T10:00:01.000000Z app\n\
             2026-10-21T10:00:02.000000Z! run\n"
        );
        let got: Vec<_> = text.lines().map(|l| unstamp(l).unwrap()).collect();
        assert_eq!(
            got,
            [
                (LogView::App, "2026-10-21T10:00:00.000000Z", "old"),
                (LogView::App, "2026-10-21T10:00:01.000000Z", "app"),
                (LogView::Runtime, "2026-10-21T10:00:02.000000Z", "run"),
            ]
        );
        assert_eq!(unstamp("nostamp"), None);
    }
}
