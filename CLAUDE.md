# briqyard

The runtime under briq: any OCI image in a Firecracker microVM on servers we own. One daemon per host (`briqyardd`), a guest init (`briqyard-init`), a controller across hosts (`briqyard-fleet`), a CLI (`briqyard`). Rust workspace, AGPL-3.0.

Most work here is done by agents. Everything an agent needs is in the repo: this file says how to work, `docs/` says what and why, `docs/adr/` says what was decided and why.

## Read first

- `docs/ARCHITECTURE.md`: how a host, a guest and the fleet work.
- `docs/adr/`: every technical decision, with the research and numbers behind it. A new decision is a new ADR in the same change.
- `docs/OPERATIONS.md`: install, config fields, upgrades, what to watch.
- `docs/DEVELOPMENT.md`: the dev loop on a Mac (Lima VMs `fc` and `fc2`) and on Linux.
- `docs/KUBERNETES-MAP.md`: briqyard as the Kubernetes of Firecracker: every Kubernetes feature, its briqyard equivalent, the gap, and whose scope (would kube provide it?).

## Layout

```
crates/briqyard-api      API types and the host–guest protocol (shared by everything)
crates/briqyardd         the daemon: config, store, zfs, netw (bridge, nft, dns), fc, image, guestc, machine, ingress, api
crates/briqyard-init     PID 1 inside the guest, static musl
crates/briqyard          the CLI
crates/briqyard-fleet    placement, forwarding, host registry, bootstrap, capacity signals, the registry's backup
crates/briqyard-objstore the object store (S3 or a directory): machine backups, the registry's backup
crates/briqyard-testing  test binaries only: each exits once its parent is gone (ADR 0049)
api/openapi.yaml         the API, served at /v1/openapi.yaml
fuzz/                    cargo fuzz targets for what untrusted parties write (nightly, by hand)
hack/                    dev VM, systemd units, dev configs, the shell suites, the stress driver
docs/                    architecture, operations, development, mesh design, adr/, research/
```

## Commands

- `cargo test --workspace` runs anywhere, but CI is Linux: run it in the VM too before pushing, in a target dir of the tree's own (`CARGO_TARGET_DIR=$HOME/target-<worktree dir>`, as `hack/vm.sh` does). macOS hides Linux behaviours tests trip on (a just-written script refused as "Text file busy", coarse file times). The init's tests are Linux-only.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` are CI.
- **The VMs are shared by every checkout and session on this Mac: one at a time.** `hack/vm.sh install|restart|stop|e2e|fleet` take the lock themselves; any other suite or anything that restarts a daemon runs under it: `hack/vm-lock.sh bash -c 'hack/vm.sh install && limactl shell fc bash hack/e2e.sh'`. Edit and build outside it; hold it only while the VMs run your build. Never restart a daemon another holder is testing.
- `hack/vm.sh install` builds in the VM, installs both units, restarts them. **Always after a config field change**: an old binary refuses a new field and systemd's start limit then needs `systemctl reset-failed`.
- `hack/e2e.sh` (244 checks, one daemon; 240 without `network.host_ports`), `hack/fleet-smoke.sh` (33, through the fleet, a `host upgrade` included), `hack/fleet-two-hosts.sh` (26, needs `fc2`), `hack/fleet-restore.sh` (10, needs `fc2`: the registry's backup and restore). Run the first two on every daemon change; the last two on every fleet change. `hack/monitoring-check.sh` (18, the stack of `hack/install-monitoring.sh` in fc) on a change to the metrics, the dashboards or the stack.
- `hack/stress.py` with `hack/stress-invariants.sh`: many tenants through every feature, host invariants between phases. Run it after any change to the manager, the network or the store.
- `hack/chaos.py`: owners that check a counter on their disks through every lifecycle operation, racers that stop, start, snapshot and back up under them. Run it after a change to snapshots, backups or the lifecycle.
- Coverage: `cargo llvm-cov` in the VM. Last measure in `docs/research/2026-10-19-stress-spike.md`.
- `limactl stop fc fc2` when done.

## Rules

- **Clean primitives, not workarounds.** A sleep that papers over a race, a special case for one environment, a retry that hides a bug, a flag that exists for one test: none of it lands. Find the condition to wait on, the layer that owns the fix, the simple solution that works.
- **Generic and reused.** One way to do each thing, in one place: the daemon, the fleet, the CLI and the provider share the API types; the fleet never reimplements a daemon rule.
- **Nothing fancy.** No trick, no clever abstraction, no feature ahead of a need. The simplest code that is correct and testable.
- **Step back before finishing.** Re-read the change against the rules above and the ADRs. Remove what a reader would not understand without you.
- **Every decision is an ADR.** Made in chat, in a review or in a benchmark: `docs/adr/NNNN-slug.md` in the same change, with the numbers that drove it. Research that informed a decision goes in `docs/research/` and the ADR links it.
- **Docs are compact.** Short sentences. Say it once. A table over a paragraph. Update the doc in the same commit as the code; the counts in `docs/DEVELOPMENT.md` match the suites.
- **A test ends what it starts, on any exit** (success, failure, panic, timeout, Ctrl-C; ADR 0049). A suite's one trap on EXIT, INT, TERM and HUP ends its own children by pid and destroys what it made; a test's child ends with the test or its parent, and a wait on a stand-in has a bound. Signal only the pids you recorded, never a name pattern.
- **Every bug found by a suite gets a unit test** that fails without the fix, before the fix.
- **Test on the Mac first.** Real servers cost money; a bug found in the VM is a bug not found on a paid host.
- The API stays briq-shaped (tenant, name, metadata `briq_id`); a new field gets its OpenAPI entry and its CLI column in the same change.
- Errors carry what failed and what was being done. The daemon logs one JSON line per event, nothing else on stdout. Never log a token or a secret.
- Lima and Mac specifics live only in `hack/config.dev.yaml`, `hack/vm.sh` and `docs/DEVELOPMENT.md`.
- **Native primitives, not another platform's workarounds.** Nothing here exists to match another platform's limitation or to keep a workaround for one working; when the control plane above carries such a workaround, briqyard offers the native primitive and the control plane drops it.
- **This repo is public: no strategy, marketing, competitor names or business internals** in files, comments, commit messages, PR titles or PR bodies. No pricing, plans, billing or cost decisions, rollout plans, or another platform named as a comparison: describe the technique or the number instead of who does it. No personal paths or private locations. Open-source components (Firecracker, ZFS, Cloud Hypervisor, Kubernetes as the reference model) may be named, and a hosting provider in a factual runbook step (a server bought by hand, OVH's vRack).

## Git

- **Every change goes through a PR.** Never commit or push to `main`. One branch per task (`feat/…`, `fix/…`, `docs/…`) in its own worktree: `git worktree add ../briqyard-<task> -b <branch> origin/main`. This checkout stays on `main`.
- A PR body says what was built, the checks with their numbers (unit, clippy, e2e, fleet suites), the choices to review, and its merge order when it depends on another PR. A draft while still pushing.
- A reviewer approves every PR before a merge. Its findings are fixed on the branch and checked again. Merge with a merge commit once CI is green; a PR that conflicts with one merged before it is updated on its own branch, its checks run again.
- Delete the worktree and the branch once merged.
- The control plane's adapter for briqyard (`BriqyardProvider`) lives in briq's own repository and follows that repo's rules.
- Never commit `target/`, `bin/`, `.env`, a token or a key.

## Hand-off

At the end of a session: the ADRs for what was decided, the suite counts and the coverage number in `docs/`, and a short note in the commit message of what is next. The next agent starts from the repo alone.
