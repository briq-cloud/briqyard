# ADR 0116: The console is read in pages from the tail, with opaque cursors

Date: 2026-11-06 · Status: accepted

## Context

`GET /v1/machines/{id}/logs` answered from a byte offset forward (`since`), with a hard cap of 1000 lines and a `next` offset. A reader that wants the latest lines of a long-running machine had to walk the whole console from its start, and a page of the `app` view (ADR 0115) could be empty while the console held thousands of runtime lines.

## Decision

**The default page is the tail.** With neither `before` nor `after`, the response is the newest `limit` lines of the view. Every page lists its lines oldest first, whichever way it was read.

**Parameters.**

| Parameter | Meaning |
|---|---|
| `limit` | lines per page; default 200, clamped to 1–1000 (a larger value is not an error) |
| `before` | the page ending where this cursor stands (older lines) |
| `after` | the page starting where this cursor stands (newer lines); an empty value is the oldest byte still stored |
| `view` | `app` (default) or `runtime` (ADR 0115) |
| `follow` | NDJSON stream; may take `since` (a byte offset) and `view` only |

`before` with `after` is `400 invalid`. A non-numeric cursor is `400 invalid`. `since` on a page and `before`, `after` or `limit` on a follow are `400 invalid`: each belongs to one mode. Clamping `limit` keeps a client that asks for "everything" working; the other cases name a request that has no meaning.

**Response: `{lines, before, after, hasOlder, hasNewer}`** (camelCase: the shape the control plane consumes, fixed with the design). `before` is the cursor to read older lines, `after` the cursor to read newer ones (the CLI prints it each time, so a reader can poll from the end). `hasNewer` is true while any byte follows, a line still being written included; the next page may then be empty. The old `next` is gone: `after` replaces it. This breaks a reader of the old response, which is why the control plane moves with it (the `since` form of a follow is kept).

**A cursor is opaque and covers every byte the page scanned**, including lines the view filtered out. A page of the `app` view over a console that is all runtime lines is empty but its cursor still moves, so a client following the cursors reaches the end and never stalls on a run of filtered lines. A cursor is today a byte offset in the console, which rotation (ADRs 0021, 0025) does not change; clients must not read it.

**Reading.**

- Forward (`after`, and the follow's backlog): scan lines from the cursor, keep those of the view, stop at `limit` lines or after `SCAN_MAX` bytes.
- Backward (the tail, `before`): scan windows of 64 KiB back from the cursor. A window starts on a line start (the byte before it is a newline), so a line is never cut. Stop at `limit` lines or after `SCAN_MAX` bytes.
- `SCAN_MAX` is 4 MiB: one request reads at most that much, whatever the console holds. When it is reached before `limit` lines are found the page is short or empty, `hasOlder` or `hasNewer` is true, and the cursor stands where the scan stopped.
- A last line without its newline is not consumed: it is the line the writer is still writing. `after` stays before it and the next page returns it whole.
- A cursor older than the oldest stored byte (the console rotated) is read from the oldest byte; `hasOlder` is false there.

## Alternative considered

Line numbers or timestamps as cursors. Rotation drops the oldest file, so a number would shift, and a timestamp is not unique; neither says where the scan stopped inside a filtered run.

An index file of line offsets. More to keep consistent across rotation, crashes and the writer's appends, for a console that one linear read of at most 4 MiB serves.

A 400 for a `limit` over 1000. The old endpoint capped silently; a client that asks for more and gets the maximum still works.

## Consequences

- The latest lines of any console cost at most `SCAN_MAX` bytes of reading, not the console's length.
- A client may receive a short or empty page with `hasOlder` true and must keep paging by cursor; a page is not the end until `hasOlder` (or `hasNewer`) is false.
- A line longer than `SCAN_MAX` is skipped by a backward page: the scan finds no line start, so the cursor moves to the bottom of the scan (inside the line) and the next page reads on before it. A cursor inside such a line is a position, not a line start: a forward page from it returns the rest of that line, cut. A forward page from a line start reads such a line whole. The writer does not bound a line.
- The CLI prints the lines on stdout and the cursors on stderr (`(older: --before X)`, `(newer: --after X)`), so a pipe stays clean.
- `since` on a page is refused, where it used to work. The briq side moves to `before` and `after` in its own change.
