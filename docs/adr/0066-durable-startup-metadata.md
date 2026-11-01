# ADR 0066: Confirm durable directories and host identity before recovery

Date: 2026-10-31 · Status: accepted

## Context

Atomic replacement makes a whole record visible. It does not prove that the directory entry
survives a crash: the containing directory also needs a sync. A failure after rename cannot
be treated as a failed create with nothing published. Existing record callers sometimes
release reservations or attempt compensation when a save fails. Changing their error
contract requires a separate lifecycle audit.

Host identity is a smaller safe boundary. The manager establishes it before reconstructing
networks, recovering guests or serving requests. Refusing startup on uncertain storage keeps
that boundary explicit. An existing visible identity may itself come from an interrupted
publication; reading it successfully is insufficient.

## Decision

Keep `write_private`, generic record writes and deletion unchanged. Add a strict publisher
used by Store initialization and host identity establishment:

- Exclusively create an unpredictable 0600 temporary beside the target, without following
  symlinks. Sync its contents, rename, then sync an already-open parent directory.
- Distinguish errors before replacement from uncertain publication. A rename error is
  uncertain even when the caller did not observe a replacement. Never remove the target
  as compensation. Remove only the temporary exclusively created by this invocation.
- Confirm intended bytes through an open regular file, sync it and its parent, then check
  the pathname still names the same file and bytes. A different target is a conflict;
  confirmation never rewrites it. The owner serializes writers to the logical target.
- Publish the Store directory ancestry from the filesystem root outward, then each direct
  record directory. Sync existing entries too, so retry repairs an interrupted directory
  publication. Tighten only Store directories and newly created ancestors to 0700.
- Serialize host-ID read/create/confirmation with a dedicated `flock` file that is never
  unlinked. Preserve existing identity bytes in their raw UTF-8 format. Refuse symlink
  identity/lock files. Any failure aborts manager initialization before recovery or serving.

The lock serializes initialization across processes. It is not a lease for an entire daemon
lifetime. Unique temporary names do not implement compare-and-swap. The filesystem and
storage stack must honor successful syncs; fault injection does not model a power loss.
Earlier startup work, including pool unlocking, still precedes this barrier.

## Scope and validation

Tests inject scoped filesystem failures with real temporary directories. They cover partial
writes, every publication stage, rename with a lost result, existing-ID repair, persistent
barrier failure, directory repair, file replacement conflicts, concurrent initializers,
permissions and temporary collisions. Legacy record formats and writer behavior are retained.
Native source tests and Linux source tests are separate checks. Linux lifecycle, fleet and
stress validation remain required before merging; no live validation is implied by the
fault-injection tests.

This change does not establish durable machine checkpoints or change suspend, snapshot,
resume, quotas or wire schemas. The next checkpoint work must migrate record owners to
explicit publication and consumption fences before using this primitive for those transitions.
