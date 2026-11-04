# ADR 0108: CI builds once per cache

2026-11-04 · Accepted

## Context

Run 41902737735 (`ci`) and 41902737838 (`native`) on PR #156:

- `check` took 7.9 min. Its last step, `cargo build --release --workspace`, took 101 s and nothing reads its output.
- The Actions cache is at its 10 GB limit and its oldest entry is under a day old. Each PR saved 3 x 367 MB: rust-cache adds the job id to its key, so `suites`, `more-suites` and `two-hosts` each saved their own copy of the same release build.
- `native` does not run on a push, so the entries `main` holds come only from manual dispatches. A PR restores from `main`'s entries or its own, so a PR restores an older entry of `main`'s by prefix, or its own.
- A draft that is still being pushed runs the whole `native` batch on every push.

## Decisions

| Decision | Setting |
|---|---|
| `check` | No release build: `cargo test` and `clippy` already compile the code. They do not run the release profile's LTO and link: a failure only there now shows in `native` (not required, skipped on a draft), in `native-cache` after the merge, or at the tag |
| Cache key | `native` jobs use `shared-key: native`, so `suites`, `more-suites`, `two-hosts` and `measure` read one key |
| Who saves | `check` and `native-cache` on a push to `main` (`save-if: github.ref == 'refs/heads/main'`). `native` never saves (`save-if: false`): a dispatch can build any ref, an old baseline included, and its entry would become the newest a PR falls back to. A PR restores and never saves |
| `native-cache` | A `ci.yml` job on push to `main`: the checkout, toolchain (with the musl target), rust-cache (`shared-key: native`) and the two build commands of `native`. It keeps a release build on `main` and writes the entry PRs read |
| Release workflow | `save-if: false`: an entry saved under a tag can be read only by that tag |
| Drafts | `native` runs on `opened`, `synchronize`, `reopened` and `ready_for_review`, and skips a draft; manual dispatch is unchanged. `check` runs on a draft: it is a required check |
| `ci` concurrency | Group `ci-<PR number or sha>`; a new push cancels the PR's older run, never a run on `main` |

**The key lines up.** The pinned rust-cache (`d1527c8f`, v2) builds the key as `v0-rust-<shared-key>-<OS>-<arch>-<hash>`: with `shared-key` the job id is left out. The hash covers `rustc -vV`, the `CARGO*`, `CC*`, `CFLAGS*`, `CXX*`, `CMAKE*` and `RUST*` environment variables, `Cargo.toml` and `Cargo.lock`, and the toolchain files. `native-cache` uses the same runner image, the same pinned toolchain action with `toolchain: stable` and the same target, sets no job-level environment variable, and runs the same build commands, so the key is the one `native` computes for the same commit. A PR that changes `Cargo.lock` misses the exact key and restores the newest `main` entry by prefix.

**What stays open.** Whether a PR's `native` job finds `main`'s entry, and by how much its build time falls, can be read only after the first push to `main` with this change. The key holds `rustc -vV`: after a new stable, a PR finds no entry until the next push to `main` saves one.

## Consequences

- One 367 MB entry per `main` commit that changes the dependencies replaces three per PR; the cache stays under its limit longer.
- `main` pays one release build per push in `native-cache`. It is not a required check.
- A draft PR has no native evidence; marking it ready starts the run (`AGENTS.md`).
