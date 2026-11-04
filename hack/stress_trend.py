"""The churn phase's verdict on the daemon's memory, open files and threads (standard library only).

A reading after one cycle swings with the allocator's timing; a leak raises the floor. So the
verdict is on floors (the least of several readings once the namespaces are empty and the
daemon is idle) and on their trend over the cycles after the first, which fills caches and pools.
"""


def floor(readings):
    """The settled value of one cycle: the least of its readings that exist; None when none does."""
    got = [r for r in readings if r is not None]
    return min(got) if got else None


def slope(values):
    """Least-squares slope of values against their position (per cycle)."""
    n = len(values)
    mean_x, mean_y = (n - 1) / 2, sum(values) / n
    den = sum((i - mean_x) ** 2 for i in range(n))
    return sum((i - mean_x) * (v - mean_y) for i, v in enumerate(values)) / den


def parse_daemon_line(out):
    """(rss in MB, fds, threads) from the invariants' `info daemon rss N kB, N fds, N threads; ...`
    line, or Nones. Split on text, no pattern matching."""
    for line in out.splitlines():
        words = line.replace(",", " ").replace(";", " ").split()
        if words[:3] == ["info", "daemon", "rss"] and len(words) >= 9:
            try:
                return int(words[3]) / 1024, int(words[5]), int(words[7])
            except ValueError:
                pass
    return None, None, None


def rss_verdict(floors, bound_mb):
    """(failed, message) for the floors of every cycle. Cycle 1 is warm-up and left out. The
    fitted growth is the slope times the span of the cycles judged: a leak of L MB a cycle
    reads about L times that span, allocator retention reads about nothing."""
    judged = floors[1:]
    if len(judged) < 3:
        return False, "RSS check skipped: fewer than 4 cycles"
    s = slope(judged)
    growth = s * (len(judged) - 1)
    series = ", ".join(f"{v:.1f}" for v in floors)
    msg = (f"daemon RSS floors per cycle (MB): {series}; fitted slope {s:+.2f} MB a cycle over cycles 2..{len(floors)}, "
           f"growth {growth:+.1f} MB (bound {bound_mb:g} MB)")
    return growth > bound_mb, msg


def handles_verdict(name, values, bound):
    """(failed, message) for a count that does not jitter: the least of the second half of the
    cycles after the first against the least of the first half. A transient connection in one
    reading does not count; a count that stays higher does."""
    judged = values[1:]
    if len(judged) < 3:
        return False, f"{name} check skipped: fewer than 4 cycles"
    half = len(judged) // 2
    low_first, low_last = min(judged[:half]), min(judged[half:])
    growth = low_last - low_first
    msg = f"daemon {name} per cycle: {', '.join(str(v) for v in values)}; floor {low_first} -> {low_last} (+{growth}, bound {bound})"
    return growth > bound, msg
