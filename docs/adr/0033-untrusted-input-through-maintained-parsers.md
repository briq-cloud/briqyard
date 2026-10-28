# ADR 0033: Untrusted input goes through maintained, fuzzed parsers

Date: 2026-10-27 · Status: accepted; amends ADR 0003 (the gateway's DNS, the ingress's request head)

## Context

The daemon reads bytes that someone else wrote: a guest's DNS queries on its gateway, a public client's HTTP request head at the ingress, a guest's frames over vsock, an image's tar layers from any registry. A hand-written parser of a wire format is where a panic or a misread hides, and a release build aborts on a panic (`panic = "abort"`): one packet from one tenant would take every machine of the host down with the daemon. Two of them, the DNS and the HTTP head, were parsed by hand where a maintained, fuzzed crate does the job.

## Decisions

**A wire format someone else writes is parsed by a maintained crate that is fuzzed upstream**, when one exists; what we do with the parsed value stays ours. The crate is the smallest part that parses, never a framework around it.

**The gateway's DNS decodes and encodes with `hickory-proto`** (0.26, MIT/Apache-2.0, the protocol crate of Hickory DNS, with a `message` fuzz target upstream; 0.26.2 fixed parser panics an attacker could reach), with its default features off. A query is decoded whole by `Message::from_vec`; one that does not parse, is a response, or asks nothing is dropped, as before, and never forwarded. The answer is a `Message` built from the first question: the address for A and ANY with a TTL of 5 s, NOERROR with no record for another type of a known name, NXDOMAIN otherwise, the question echoed as asked (case kept for resolvers that randomise it). The names (`<alias>.internal`, `<id>.vm.internal`), the NXDOMAIN for a source kept inside (not REFUSED, for musl) and the raw-packet forward upstream are unchanged, except that a forwarded answer is now taken only from the upstream asked (a connected socket) and only with the query's ID: another datagram is ignored until the 4 s deadline.

| | before | after |
|---|---|---|
| Parser and encoder in `netw/dns.rs` | 60 lines by hand | `hickory-proto` |
| Compression pointer in a question | dropped | followed, loops refused |
| A label holding a `.` byte | joined as a dot (could match another name) | escaped, matches nothing |
| New crates in the Linux build | | 6: `hickory-proto`, `rand` 0.10 with `rand_core` and `chacha20`, `critical-section`, `portable-atomic` |

**The ingress reads a public request head with `httparse`** (1.10, MIT/Apache-2.0, hyper's parser, fuzzed upstream; already in the tree through hyper), at most 64 KiB and 100 header lines: beyond either, 431, as before for the size. What it routes by is ours, and strict, because the machine reads the same head after us (RFC 9112 §3.2):

| Head | Answer |
|---|---|
| Not HTTP/1.x (bad request line, a space before a colon, a folded line, a bare CR, a NUL) | 400 |
| No `Host`, an empty one, a port that is not a number | 400 (was 404 `no endpoint for`) |
| Two `Host` lines | 400 (was: the first one routed) |
| Absolute-form target (`GET http://a.example/`) | routed by its authority; 400 when `Host` says another |
| `Host` of no endpoint | 404, as before |
| A head ending in bare `\n` lines | routed (was: waited for `\r\n\r\n` until 64 KiB) |

Only the first request of a connection is read; the rest is spliced, as before.

**What stays ours is fuzzed here**: `cargo fuzz` targets in `fuzz/` (its own workspace, nightly only, run by hand, `../DEVELOPMENT.md`) for every decoder an untrusted party feeds. `briqyardd` is a library plus its binary so the targets reach them. A crash's input becomes a unit test with its fix. Not in CI: the stable job cannot run them, and a nightly job is minutes billed for a run too short to find much.

| Target | What it feeds | Checks | Last run: 2026-10-28, 300 s each on the corpus of a 600 s run, aarch64 VM |
|---|---|---|---|
| `guest_frames` | the init's frames: exec output to its exit, the exit report, an answer | no panic | 4.0 M runs, cov 1732, no crash |
| `session_input` | an exec session's query and client messages | no panic | 4.0 M runs, cov 1619, no crash |
| `layer_extract` | tar entries built from the input (any name, type, link, mode), raw names | nothing beside the root changes | 0.46 M runs, cov 1416 (the `openat2` extractor, ADR 0039), no crash |
| `dns_query` | a guest's query | every answer parses back | 3.3 M runs, cov 2860, no crash |
| `ingress_head` | a public request head | a routed host is non-empty and lowercase | 4.8 M runs, cov 525, no crash |

## Rejected

- **`hickory-server`'s `RequestHandler`**: it brings its own listener, TCP, and a request/response framework, for a handler that is one lookup; our listener per gateway, the per-source policy and the raw forward would sit beside it rather than in it.
- **Keeping the hand parser and fuzzing it**: fuzzing finds what it reaches; a crate fuzzed upstream by people who know the format, and used by every Hickory resolver and server, has been exercised far more than ten minutes here would.
- **hyper's server for the ingress**: it would own the connection, and the ingress splices bytes after the head so WebSockets and streaming pass untouched.
- **`simple-dns`, `domain`**: smaller or broader; `hickory-proto` is the one most deployed in Rust and the one whose security fixes we can follow.
