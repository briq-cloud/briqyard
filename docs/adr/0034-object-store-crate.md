# ADR 0034: The object store is Apache Arrow's `object_store`, on our reqwest

Date: 2026-10-27 · Status: accepted; amends ADR 0008 (the store's client) and ADR 0032 (what an error may say)

## Context

`briqyard-objstore` (ADR 0032) held our own S3 client: rusty-s3 presigned each request, and the crate wrote the multipart upload (32 MB parts, one at a time), the list's pagination, the error mapping and the streaming around it, 532 lines with tests. It had no retry: one dropped connection in a 50 GB `zfs send` failed the backup, and the next one started whole again an hour later. Apache Arrow's `object_store` does all of that: the S3 client of DataFusion, Polars, delta-rs and InfluxDB, Apache-2.0, released monthly; multipart writes with parts in flight at once, retries with backoff, a get that resumes a cut stream with a ranged request, and a local file system store behind the same trait.

## Decisions

**`object_store` 0.14 for both stores, behind the crate's own API.** `ObjectStore::open`, `put` (a stream), `get` (a stream), `put_bytes`, `get_bytes`, `list`, `delete`, `describe`: the callers (the daemon's backups, the fleet's registry backup) did not change. `s3://bucket/prefix` is `AmazonS3` under a `PrefixStore`; `file:///path` is `LocalFileSystem`, so the e2e suite's directory store runs the same calls as a bucket. A `put` is `object_store`'s `BufWriter`: a stream shorter than a part is one PUT, a longer one a multipart upload of 32 MB parts, four in flight (at most 160 MB of a stream in memory; 10,000 parts make 320 GB an object); a stream that fails midway aborts its upload. A `get` is the object's byte stream, never collected but by `get_bytes`. Credentials stay `BRIQYARD_S3_ACCESS_KEY` / `BRIQYARD_S3_SECRET_KEY`, given to the builder; nothing is read from `AWS_*`.

**Retries: 10 with backoff from 100 ms doubling to 15 s, within 10 minutes.** `object_store` tries again a connection that did not open, a 5xx and a 429; a timeout or a cut connection only for an idempotent request, which every S3 request is in `object_store` 0.14, a multipart completion included: a completion re-sent after its answer was lost fails with `NoSuchUpload`, and the backup is made again. Plain HTTP is allowed only to an `http://` endpoint (the connector honours the builder's `allow_http` with `https_only`). A get cut midway resumes at the byte it reached, checked by ETag. A request is given 300 s to send its body and get its answer's head, then 300 s between two pieces of an answer (`read_timeout`): a stalled connection fails and is tried again, a long download is not cut. The fleet's 30 s deadline on the registry's write stays its own, around the call.

**The HTTP client is ours: `object_store`'s `aws-base` feature with an `HttpConnector` over the workspace's reqwest 0.12.** `object_store` 0.14's `aws` feature brings reqwest 0.13 with aws-lc-rs and the platform verifier: a second reqwest, hyper-rustls and rustls build, and a C crypto library the workspace avoids (ADR 0020 chose ring). With `aws-base`, `fs` and `ring`, signing is ring and every request goes through the connector (80 lines): one reqwest, one TLS stack, webpki roots as before.

**An error says what failed, the object's URL and the S3 error code; never a credential.** `object_store` signs in the `Authorization` header: no URL carries a signature now, so its errors keep the URL (`Error performing PUT https://…/bucket/backups/m_…/root/….zfs?partNumber=3&uploadId=…`), which says which object failed. What it would add from the wire is cut at the connector: a connection error goes without its URL (`reqwest::Error::without_url`), and an error answer's body becomes its `<Code>` alone (`SignatureDoesNotMatch`, `NoSuchBucket`): an S3 error body echoes the access key id, the string to sign and the signature provided. Unit tests check both: a refused connection and a 403 whose body holds an access key id and a signature, on every call. `object_store`'s own retry lines (`info`, the status or the transport error's kind) go through the daemon's and the fleet's JSON log; they carry no URL.

**Measured** (the crate without its tests; the workspace's lock file; `cargo tree -e normal`):

| | before | after |
|---|---|---|
| `briqyard-objstore`, lines | 431: presigning, our multipart, list pagination, error mapping | 300: `open`, `put` over `BufWriter`, the connector (80) |
| lines removed / added | | 332 / 201 |
| packages in the lock file | 378 | 381 |
| crates built (normal deps) | 404 | 412 |
| reqwest, hyper, h2, rustls, ring | one each | one each; no aws-lc |

What comes in: `object_store`, `crc-fast`, `itertools`, `either`, `spin`; second versions of `nix` (0.31, its local store), `rand` 0.10 with `rand_core`, `chacha20` and `getrandom` 0.4 (backoff jitter), `digest` 0.11. What goes: `rusty-s3` and its `md-5` 0.10, `quick-xml` 0.37 and `time-macros` (`md-5` and `quick-xml` come back at their next versions). Against MinIO from the Mac (debug build, `real_bucket_round_trip`): 64 MB in two parts and a short last one, put in 2.9 s, read back, listed, deleted; a wrong secret answers `403 Forbidden: SignatureDoesNotMatch`.

| Rejected | Why |
|---|---|
| `object_store` with its `aws` feature | reqwest 0.13 next to our 0.12, and aws-lc-rs (a C build) next to ring |
| Moving the workspace to reqwest 0.13 | oci-client 0.14 is on 0.12; a change across the CLI, the daemon and the fleet for one dependency |
| `object_store` 0.12 (the last on reqwest 0.12) | an old line, fixes land on 0.14; the connector is the documented way to bring a client |
| Keeping our client and adding retries | the multipart, resume and backoff code is what the library is |
| `opendal` | a larger surface (dozens of services), its own layers; we need S3 and a directory |
| `aws-sdk-s3` | the AWS SDK and its runtime (smithy, aws-lc), hundreds of crates |

## Local directory cleanup (2026-10-31)

**Enable `LocalFileSystem::with_automatic_cleanup(true)` for a `file://` store.** After an object is deleted, `object_store` 0.14.2 uses nonrecursive `remove_dir` on its empty parent directories, stopping at the canonical configured store root or at the first nonempty directory or error. Deleting the last backup stream and record therefore removes the empty machine prefix. Sibling objects, files and an upload's staged file keep their directories nonempty; the configured root stays. A missing object's delete remains success. There is no scan or migration of directories left by earlier deletions, and no recursive removal.

This is best-effort directory cleanup, not a durability guarantee: the vendor's standalone `delete_stream` passes `fsync=false`, even when its write-fsync option is enabled. A concurrent writer either keeps the directory nonempty with its staged file or creates its required directories when it opens a new staged upload. The wrapper adds no locking or retry. Local tests check nested pruning, the configured-root boundary, sibling data, idempotence and an upload held open across a deletion.

## Consequences

- A backup's upload survives a dropped connection or a provider's 503; up to four parts go at once, so a fast link is used (one part at a time before).
- `LocalFileSystem` writes an object to a temporary file and renames it, without the `fsync` our directory store did: a power cut can leave a short last object. The directory store is for development and a host's own second disk (ADR 0008); a bucket is the production store.
- An S3 error now names the bucket and the object's key in logs and events (no credential). The 503 a host gets from the fleet still says only that the backup failed (ADR 0032).
- A provider's bucket is still to run: `cargo test -p briqyard-objstore -- --ignored` with `BRIQYARD_S3_TEST_STORE`, `_ENDPOINT`, `_REGION` and the credentials, run against MinIO in development (above); Scaleway when an account is open. The daemon's and the fleet's suites use a directory store, the same calls.
