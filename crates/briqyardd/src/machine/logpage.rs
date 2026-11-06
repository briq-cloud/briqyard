//! Pages of the console (ADR 0116): chronological, of one view, from a cursor or from the tail.
//!
//! A cursor is an offset in the whole console, at the start of a line (inside one only when a
//! backward page skipped a line longer than `SCAN_MAX`), and covers every byte scanned, the
//! other view's lines included, so a page that found nothing still moves. A request scans at
//! most `SCAN_MAX` bytes.

use super::exec::parse_log_line;
use super::*;
use std::io::{BufRead, Read};

/// Where a page starts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LogAt {
    /// The newest lines.
    Tail,
    /// The lines before the cursor, ending at it.
    Before(u64),
    /// The lines from the cursor.
    After(u64),
}

/// Lines a page holds unless the caller asks, and the most it holds.
pub const DEFAULT_LIMIT: usize = 200;
pub const MAX_LIMIT: usize = 1000;

/// The most a page reads from the console, so a view that is rare in a large console answers
/// with an empty page and a moved cursor instead of reading all of it.
pub(super) const SCAN_MAX: u64 = 4 << 20;

/// The window a backward scan reads at a time.
const WINDOW: u64 = 64 << 10;

/// Lines of one view and the console range they were read from.
pub(super) struct Page {
    pub lines: Vec<api::LogLine>,
    /// The first byte of the range, where the page before it ends.
    pub from: u64,
    /// The first byte after the range, where the page after it starts.
    pub to: u64,
    /// Whether bytes remain after `to`.
    pub more: bool,
}

/// Up to `limit` lines of `view` from `from` on, reading at most `scan` bytes.
pub(super) fn forward(
    dir: &Path,
    from: u64,
    limit: usize,
    scan: u64,
    view: api::LogView,
) -> std::io::Result<Option<Page>> {
    let Some((at, mut r)) = console::read_from(dir, from)? else {
        return Ok(None);
    };
    let (mut pos, mut lines) = (at, Vec::new());
    let more = loop {
        if lines.len() == limit || pos - at >= scan {
            break true;
        }
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 || !line.ends_with('\n') {
            break false;
        }
        pos += n as u64;
        let (of, line) = parse_log_line(&line);
        if of == view {
            lines.push(line);
        }
    };
    let more = more && pos < console::end(dir)?;
    Ok(Some(Page {
        lines,
        from: at,
        to: pos,
        more,
    }))
}

/// Up to `limit` lines of `view` that end at or before `to`, the newest ones, oldest first.
pub(super) fn backward(
    dir: &Path,
    to: u64,
    limit: usize,
    view: api::LogView,
) -> std::io::Result<Option<(Page, bool)>> {
    let Some((oldest, _)) = console::read_from(dir, 0)? else {
        return Ok(None);
    };
    let end = console::end(dir)?;
    let asked = to.clamp(oldest, end);
    let floor = asked.saturating_sub(SCAN_MAX).max(oldest);
    // The newest complete line ends here; a line the daemon is still writing is not one.
    let mut top = asked;
    let (mut from, mut win) = (asked, WINDOW);
    let mut newest_first: Vec<Vec<(u64, api::LogLine)>> = Vec::new();
    let mut count = 0;
    while from > floor && count < limit {
        let w = from.saturating_sub(win).max(floor);
        let (start, kept, partial) = window(dir, w, from, oldest, view)?;
        if from == asked {
            top = partial.unwrap_or(asked);
        }
        if start >= from {
            // Not one line starts in the window: read more of it.
            win *= 2;
            if w == floor {
                // A line longer than the scan: skipped, and the cursor still moves.
                from = floor;
                break;
            }
            continue;
        }
        win = WINDOW;
        count += kept.len();
        newest_first.push(kept);
        from = start;
    }
    let mut lines: Vec<(u64, api::LogLine)> = newest_first.into_iter().rev().flatten().collect();
    let before = match lines.len().checked_sub(limit) {
        Some(extra) if extra > 0 => {
            lines.drain(..extra);
            lines[0].0
        }
        _ => from,
    };
    let lines = lines.into_iter().map(|(_, l)| l).collect();
    Ok(Some((
        Page {
            lines,
            from: before,
            to: top,
            more: asked < end,
        },
        before > oldest,
    )))
}

/// What `window` read: where its first line starts, the lines of the view with their offsets,
/// and where a last line that has no end yet starts.
type Window = (u64, Vec<(u64, api::LogLine)>, Option<u64>);

/// The lines of `view` starting in `[w, to)`, from the first line that starts at or after `w`.
fn window(dir: &Path, w: u64, to: u64, oldest: u64, view: api::LogView) -> std::io::Result<Window> {
    let back = w.saturating_sub(1).max(oldest);
    let Some((at, mut r)) = console::read_from(dir, back)? else {
        return Ok((to, Vec::new(), None));
    };
    let mut start = at;
    if w > oldest {
        // `w` may be inside a line: its start belongs to the window before.
        let mut skipped = Vec::new();
        start += r.read_until(b'\n', &mut skipped)? as u64;
        if skipped.len() == 1 && skipped[0] == b'\n' {
            start = w;
        }
    }
    let mut r = r.take(to.saturating_sub(start));
    let (mut pos, mut kept, mut partial) = (start, Vec::new(), None);
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if !line.ends_with('\n') {
            partial = Some(pos);
            break;
        }
        let (of, parsed) = parse_log_line(&line);
        if of == view {
            kept.push((pos, parsed));
        }
        pos += n as u64;
    }
    Ok((start.min(to), kept, partial))
}
