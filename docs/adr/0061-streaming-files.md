# ADR 0061: Raw file streams with an atomic upload

Date: 2026-10-30 · Status: accepted

## Context

The JSON `/files` API buffers a whole file, represents it as base64 twice (HTTP and
vsock), and encounters HTTP's 2 MiB JSON body bound before the guest's 4 MiB frame
bound. Large files need a stream through the runtime, without a shell or utilities
in the image. A single file is the needed primitive; callers can stream an archive
as an ordinary file when their application needs one.

## Decisions

**Add GET and PUT `/v1/machines/{id}/files/content?path=…`.** The body is raw bytes.
PUT accepts a known `Content-Length` or an unknown-length HTTP body; both are counted
and bounded. GET answers with `Content-Length`. PUT's optional `mode` is octal permission
bits, including `0000`, never setuid, setgid or sticky. When absent it preserves an existing
regular destination's permission bits; a new file or a final symlink replacement defaults
to `0644`. The CLI's existing `machine put` and `get-file` use this endpoint and encode the
path as a query parameter. The fleet forwards both directions without buffering the file.
The existing JSON operations remain for clients and inits that already use them.

**A framed handshake, then bounded binary chunks for uploads, raw bytes for downloads.**
Additive guest operations `put_stream` (path, optional file_mode and size) and `get_stream`
(path) answer `ready` or `error`. A PUT chunk is a four-byte big-endian length followed by
at most 64 KiB of raw data. A zero length commits; the host sends it only after the HTTP
body ended successfully. Both sides count bytes against the 1 GiB cap and the optional
declared total. A truncated chunk, EOF without the terminal or a mismatched total never
commits. This one format accepts both known and unknown sizes, without vsock half-close
semantics. The guest computes SHA-256 while writing and answers `ok` with `size` and
`sha256` after commit; HTTP answers 200 with those fields as JSON.

GET's ready carries `size`; exactly that many raw bytes follow. An old init answers its
usual unknown-op error, which names the init and the image-change upgrade path; there
is no fallback through exec. After a GET's ready, failure is a short stream, never a
framed error mistaken for file bytes. A download is not a file snapshot: concurrent
growth is excluded by its initial size; truncation fails the response.

**Probe capability before consuming upload input.** New inits explicitly advertise
`file_stream_v1: true` in their live pong; absence means false. The daemon's narrow
`GET /v1/machines/{id}/files/capabilities` returns that flag, the pong's init version,
and `legacy_max_bytes` (1 MiB) and `native_max_bytes` (1 GiB). The fleet forwards it
normally. Version numbers do not establish capability: development builds can have the
same version, and running guests retain their init across host upgrades. Probe failures
propagate; they never enable fallback. Raw endpoints still refuse an unsupported init.

The CLI probes before reading upload input. An unsupported init keeps one JSON operation
up to 1 MiB: reject a known larger size before reading, otherwise read at most 1 MiB plus
one detection byte before deciding; never send an oversized legacy PUT. Legacy response
JSON and encoded base64 lengths are bounded before decoding. There is no retry of input
already consumed, disk spooling, chunk-file assembly or guest exec. Legacy checksums are
unverified. The legacy JSON calls keep their existing mode, symlink and partial-write
semantics, without the new primitive's atomic or path guarantees. An old init's JSON GET
uses `fs::read` before encoding: a large file can allocate in that guest before its answer
is refused; the client-side bound does not remove that limitation. An image change
rebuilds the root disk with the current init for larger native transfers.

**Write a temporary file beside the destination, then rename.** The guest writes
`0600` through the open file descriptor, flushes and syncs its contents, sets its
explicit or preserved mode through the descriptor, and atomically renames it into place.
A failed or cancelled upload unlinks its temporary file. It can leave newly created parent
directories. An existing destination stays untouched until commit. Temporary names cannot
equal the destination basename; cleanup ends permanently after a successful rename. Its final
symlink or hard link is replaced itself, never its target. Concurrent uploads are
last successful rename wins. A guest crash may leave a temporary file; the API
does not claim that a rename survives a guest crash before the directory is synced.

**Resolve directories by descriptors without symlinks.** An absolute path, at most
4096 bytes, with no empty, `.` or `..` components. Starting from the guest's root,
each directory is opened with `O_DIRECTORY | O_NOFOLLOW`; a PUT makes missing
parents with `mkdirat`. The last component is opened `O_NOFOLLOW | O_NONBLOCK`
for a GET, then checked to be a regular file (a FIFO cannot block the init). All
upload creation, cleanup and rename calls use the pinned parent descriptor.
Renaming a directory cannot redirect the operation through a substituted symlink.
Parent symlinks are deliberately refused; callers use the resolved directory path.
No guest filesystem is mounted or parsed on the host.

**Fixed resource bounds.** At most 1 GiB per file, 16 transfers per daemon, four
per guest; the next transfer is refused, never queued. Each transfer lasts at most
900 s, each data read or write at most 60 s without progress. A file buffer is
64 KiB. Host downloads use one queued chunk and one being read, with backpressure
and cancellation: a dropped or stalled HTTP reader ends the guest connection and
releases machine use. A transfer holds machine use through its handshake and data;
it requires an already running machine. The fleet uses one queued response chunk
and a 900 s bound; it propagates the daemon's declared length so early EOF fails
at the client. Limits are in the shared API crate, not new configuration knobs.

| Rejected | Why |
|---|---|
| Raising JSON/frame bounds | Whole-file memory and base64 expansion still grow with size |
| Archive extraction in the runtime | Adds entry types, link semantics and extraction limits beyond moving one file |
| Chunk files plus guest exec | Requires guest utilities and a partial-file assembly protocol |
| Upload directly over the destination | Cancellation exposes a partial file |
| EOF alone commits the vsock upload | A cut HTTP body could commit an incomplete transfer |

## Validation

Regression tests cover binary and empty files, a 5 MiB transfer above both JSON and
frame bounds, known and unknown lengths, incomplete and uncommitted uploads, oversized
chunks and counted totals, cleanup, explicit and preserved modes, hashes, temporary-name
collisions, symlink and hard link replacement, parent symlink refusal, a renamed parent directory, special
files, path and size bounds, unknown old-init operations, HTTP-body failures,
idle expiry, and fleet and CLI forwarding with encoded paths.
