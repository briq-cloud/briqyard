# ADR 0101: The init's digest changes only when the init does

2026-11-04 · Status: accepted; amends ADR 0027 (what the init reports) and extends ADR 0076 (seeds bound to the init's SHA-256)

## Context

A sandbox seed is bound to the SHA-256 of the init in its root disk (`templates.sandbox_recipes[*].init_sha256`, ADR 0076; adoption and launch compare it with the `pong`'s `init_sha256`). A digest that changes forces every seed to be built, qualified and sealed again.

v0.1.19 to v0.1.20 changed nothing in `crates/briqyard-init` or the guest protocol, yet the digest went `4a105e6c` to `51c38806`. Two causes, each measured by building the musl init (`--release --locked -p briqyard-init`, release profile) and comparing digests:

| Build | Digest |
|---|---|
| release 0.1.20, commit `000000000000` | `c5b0ebae` |
| the same, commit `ffffffffffff` | `64dd1074` |
| release `0.1.20-digest-check`, commit `ffffffffffff` | `abe637e8` |

Built on a Mac for `x86_64-unknown-linux-musl` with `rust-lld`; CI's digests differ in value, not in behavior.

1. **The commit.** The init reported `briqyard_api::VERSION` (`0.1.20+<commit>`, ADR 0027) in its `pong` and exit report. The string is built into the binary from `briqyard-api`'s `build.rs`, so every commit changed the init.
2. **The package version.** With the commit out of the init (the version crate split), a release alone still changed it: `7beb2a57` for 0.1.20 and `562f7167` for `0.1.20-digest-check`, the commit no longer in the binary. Cargo hashes a package's version into its metadata and so into its symbols. `briqyard-init` and `briqyard-api` followed the workspace version.

## Decision

**The init's identity is its bytes, and they change only when the init's code, its dependencies or the toolchain do.** A release or a commit outside those leaves the digest, and so every seed bound to it, unchanged.

- **The version moves out.** `briqyard_version::VERSION` (the new crate `briqyard-version`, with the `build.rs`) is what the daemon, the fleet and the CLI say; the init does not link it. The init reports `briqyard_api::version::GUEST_VERSION` instead, a constant in source: a release at or after every gate the daemon checks (today `SESSIONS`, ADR 0029), not the release the init was built in. It changes in the change that adds a version gate, set to that release, and never otherwise. Test: it is a release number, not later than the build's, and not before `SESSIONS`. A forgotten bump fails closed: a gate above `GUEST_VERSION` makes the daemon refuse the new init (409, naming it), never accept an old one. A new daemon gate should be a capability flag in the `pong` (as `file_stream_v1` and `exec_stream_v1` are), which needs no version; a version gate, if ever, gets an assert beside `SESSIONS`'s.
- **The init's crates keep their own package version.** `briqyard-init` and `briqyard-api` are `0.0.0`, not the workspace version. `hack/release.py` leaves them out of the version bump and the lock updates.
- **CI keeps it true.** `hack/init-digest-check.sh` builds the musl init twice, the second time with another workspace version and `BRIQYARD_COMMIT`, and fails when the digests differ. It runs in the `check` job, on the runner and toolchain that built the first.

After both changes, `hack/init-digest-check.sh` builds release `0.1.20` with commit `000000000000` and release `0.1.20-digest-check` with commit `ffffffffffff`: both `8b5e3440`.

### Who read the init's version

| Reader | Use | Now |
|---|---|---|
| `machine/exec.rs` | `version::before(init_version, SESSIONS)`: an exec session is refused 409 on an init older than sessions | unchanged; `GUEST_VERSION` is `0.1.20`, after `SESSIONS` (`0.1.0`); older inits still report their release and compare as before |
| `start.rs`, `adoption.rs`, `bind.rs` | store the `pong`'s version as the machine's `init_version`; nothing compares it. A hand-over or an adoption compares `init_sha256`, not the version | unchanged |
| `guestc::with_init`, the CLI (`machine get`, file size error) | name the init in a message | unchanged; shows the guest version |
| `hack/e2e-storage.sh`, `hack/fleet-smoke.sh` | asserted `init_version` equal to the build | assert a release number |

The `version` field stays in the `pong`, the exit report and `init_version`, with the same type: the daemon still talks to a running guest of an older init (hand-over, ADR 0027) and to a new one. It now means "the guest protocol version", not "the release this init was built in"; the daemon's own release is in `/v1/status`, and the init's bytes are named by `init_sha256`. A field that said the build's commit would have kept the commit in the init.

### What still changes the digest

The init's source and what it links of `briqyard-api` (`guest`, `files`, `session`, `version`), the versions of its dependencies in `Cargo.lock`, the toolchain (`release.yml` pins `1.97.0`; a new pin is a new digest), the target and the release profile. The other bindings of a seed are not the init's: the manifest and image config digests, the kernel and VMM, the CPU template (ADR 0087, 0088) and the sizes. A release that changes one of those still re-seals.

Measured: a field added to `api::Status`, which only the daemon uses, and a rebuild left the digest unchanged (`85570f75` on both builds, musl, `--release --locked`). Code of `briqyard-api` the init does not link is dropped by the linker, so a daemon-only API change keeps the digest; a change to the modules above, or to `GUEST_VERSION`, moves it.

### The release that carries this change

The init's package version and its reported version change once, so the digest of the first release with this ADR differs from the release before it. Its upgrade notes say so. From the next release on, the digest holds until one of the causes above changes it.

## Consequences

- A release that changes nothing in the init keeps its seeds: no re-seal, and `sandbox_recipes` needs no new digest before the upgrade.
- Daemon, fleet and CLI report `release+commit` as before (`--version`, `/v1/status`, `host ls`).
- A change to the guest protocol that the daemon gates on bumps `GUEST_VERSION` with it. One that does not, leaves it.
- A pinned toolchain bump is a deliberate digest change.
