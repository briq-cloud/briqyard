# ADR 0110: `alerts` and `monitoring` run when something they read changed

2026-11-04 · Accepted

## Context

Run 41902737838 (`native`, PR #156), the two slowest entries of the `more-suites` matrix:

| Suite | Time | Why |
|---|---|---|
| `alerts` | 17.8 min | it waits out the crash-loop alert's 10-minute window; ADR 0094 forbids shortening a window |
| `monitoring` | 9.9 min | the stack's install, `monitoring-check.sh`, the Not answering alert |

Together 27.7 runner minutes on every PR the workflow triggers on. ADR 0109 puts `suites` at about 15 min, so `alerts` would set a PR's wall time. Both suites test the monitoring stack (dashboards, alert rules, the series they read), which most PRs do not touch.

## Decisions

| Decision | Setting |
|---|---|
| Selection | A `changes` job in `native.yml` lists the suites; `more-suites` takes its matrix from it (`fromJSON`). `hack/native-suites.py` holds the one table. Only `monitoring` and `alerts` are ever left out; the other four always run |
| The diff | On `pull_request`, `git diff --name-only HEAD^1 HEAD` of the merge commit: exactly what the PR changes. Any other event (a dispatch) runs every suite |
| Never reduced | A dispatch; a PR whose diff names a watched path; empty input (nothing says what changed). A release PR changes root `Cargo.toml` and `Cargo.lock` (PR #155), both watched, so it runs everything before shipping |
| A failure is red | If `changes` fails (a script error, a merge ref that cannot be checked out), the run is red and `more-suites` does not start: no suite is skipped quietly. `suites` and `two-hosts` do not depend on `changes`. A draft, `two_hosts_only` and `measure_freeze` skip `changes` and `more-suites` together, as `more-suites` skipped before |
| Visible | The step summary names the suites that run and the ones left out, and says a release PR runs them |

The watched paths, with the reason for each:

| Path | Why |
|---|---|
| `hack/monitoring/` | dashboards, alert rules, the promtool fixtures |
| `hack/monitoring-*` | the check scripts: `-check.sh`, `-alerts-check.py`, `-alert-check.py`, `-auth.*`, `-webhook-check.py` |
| `hack/install-monitoring.sh`, `hack/render-alerting.sh` | the install both suites run |
| `hack/native-ci.sh`, `hack/native-ci-more.sh` | the host and the suites' bodies |
| `.github/workflows/native.yml`, `hack/native-suites.py` | the selection itself and the jobs |
| `crates/briqyardd/src/metrics.rs`, `metrics/` | the host's series: names, labels, types |
| `crates/briqyardd/src/machine/observe.rs` | the host's lifecycle counters that `host.json` reads: boots, resumes, suspends, execs, failed starts, backups |
| `crates/briqyard-api/src/metrics.rs` | the exposition format of every series: the family header, label escaping |
| `crates/briqyard-fleet/src/signals.rs` | the fleet's series: `briqyard_fleet_*` (room, host state, refusals) |
| `crates/briqyard-fleet/src/scrape.rs` | what Prometheus scrapes: the relayed `/metrics` and the target labels (`instance`, `host`, `region`) |
| `Cargo.toml`, `Cargo.lock` (root) | the release PR, and a dependency change under the daemon |

The rules read `briqyard_host_condition`, `briqyard_pool_bytes`, `briqyard_machine_restarts_total`, `briqyard_events_total`, `briqyard_fleet_unschedulable_total` and `briqyard_fleet_largest_slot_mb`; the dashboards and `monitoring-check.sh` read the machine, warm pool and fleet series besides. Each is defined and rendered in the files above.

## Amendment: a dispatch may name its suites

A dispatch takes an optional `suites_only` input: the suites of `more-suites` to run, comma separated (`qualification`, `scale,stress`). The default is empty, which is the selection above: every suite on a dispatch, the diff on a pull request.

| Decision | Setting |
|---|---|
| Validation | `hack/native-suites.py --only` accepts only known names, each once, none empty, and prints them in matrix order. Anything else fails `changes`, so `more-suites` does not start: a typo never runs every suite or none. An unset input and an empty one are the same to GitHub, so the default is all; a value of only spaces or commas fails |
| Other jobs | `suites` (e2e, fleet-smoke, scoped execution), `two-hosts` and `measure` are skipped when the input is set; it selects among the matrix names only |
| Combinations | With `measure_freeze` or `two_hosts_only`, `changes` fails with a message; nothing else runs |
| Pull requests | The input does not exist there; the diff still decides |
| Visible | The step summary names the suites that run and the ones not selected, and says the input selected them |
| Unchanged | The harness comes from the workflow revision and the suites from the tested source; the watched paths, and so the release PR's full run, are as before |

## Consequences

- **The residual risk.** A series is defined in one place but changed by its call sites: the restart counter, the refusal counter, `backup_failed`, the host condition and the pool read are set from the machine manager, the fleet's create path and the store. A behaviour change there that breaks an alert (a restart no longer counted, a refusal no longer recorded) does not run `alerts` or `monitoring` on that PR. `native` does not run on a push to `main`, so the next release PR, or a dispatch, is the first run that sees it. That catch is by convention, since `native` is not a required check, and by then the cause is on `main`, among every PR since the last release. The relay's answers that `monitoring-check.sh` reads (`crates/briqyardd/src/api/`, `crates/briqyard-fleet/src/main.rs`) are unwatched for the same reason: those files are too broad. A crate directory is not watched whole because a counter incremented from many call sites would then watch most of `crates/`, and the saving would go.
- Saved on a PR that touches none of the paths: 27.7 runner minutes, and the wall time falls to the longest of the other jobs. A PR that touches one runs as before.
- The unit tests of `hack/test_native_suites.py` (in the `check` job) prove the decisions: a crate outside the list, docs, each watched path, a release's files, `--all`, empty input and a malformed use.
- Measured on a PR with one comment in a crate, closed unmerged (#164, run 41932481556): `changes` selected `stress`, `qualification`, `restore` and `scale`, and neither skipped suite ran. The longest suite besides `two-hosts` took 14.1 min. `two-hosts` took 21.2 min and set the run's time, 7 min of it an apt stall (ADR 0089); it took 11 to 14 min on runs without a long stall.
- Adding a suite to the matrix is a change to `hack/native-suites.py`; adding a path the two suites read is a line in its table.
- Reopen if a release PR finds a monitoring break that a watched path should have caught, or if the release PR stops being a full run.
