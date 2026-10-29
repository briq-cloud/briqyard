# ADR 0054: Monitoring beside the fleet: Prometheus and Grafana, hosts scraped through the fleet

Date: 2026-10-29 · Status: accepted; amends ADR 0021 and 0042 (the metrics token no longer shuts the API's out of `/metrics`)

## Context

Every daemon serves `/metrics` (ADR 0021) and the fleet its placement signals (ADR 0042), but nothing keeps them: `briqyard top` and `/v1/status` say what is true now, not what was true at 3 a.m. Kubernetes leaves the same gap to Prometheus (scraping the kubelets and kube-state-metrics, finding them through the API server) and Grafana (`KUBERNETES-MAP.md`, Observability).

Three things stand between a Prometheus and the hosts:

- A host's API serves TLS with a self-signed certificate the fleet pins by SHA-256 (ADR 0020). Prometheus checks a certificate against a CA, or not at all.
- Hosts come and go (`host add`, `retire`): a list of targets in Prometheus's configuration is wrong after each.
- On a real install the fleet listens on loopback behind the operator's reverse proxy (`OPERATIONS.md`, First OVH host); the hosts' APIs are on the private network.

## Decisions

**The fleet relays each host's metrics: `GET /v1/hosts/{id}/metrics`.** The fleet asks the host's `/metrics` over the client of its pinned certificate with the host's token, as every forwarded call, and answers the host's text as it is, or the host's own refusal as it is. A down host is 503 `host_down`, a host that does not answer within 5 s (a host answers from memory, ADR 0021) or cuts its answer short is 502 `host_unreachable`, the codes forwarded calls already use: to Prometheus, `up == 0` either way. A body cut short is now a 502 for every forwarded call; it was the host's status with half a body. Prometheus then needs no route to the hosts, no certificate of theirs and no token of theirs: one token, for one address.

**The targets come from the fleet: `GET /v1/metrics/targets`,** in Prometheus's HTTP service discovery format (`http_sd_configs`, refreshed every 30 s). The fleet's own `/metrics` first (`instance="fleet"`), then one target per host that may run a daemon (ready, draining, retiring, upgrading, and down: a down host stays a target so it is scraped as down; one still being bootstrapped is not), with `__metrics_path__` its relay path. Every target's address is the one the caller reached the fleet at (`Host`): `127.0.0.1:7430` beside it, the proxy's name behind one, with no setting to keep in step. A host added appears within 30 s, a host forgotten goes.

**A target's labels are what does not change with its state:** `instance` and `host` (its id) and `region`. All targets share one address, so `instance` is set, not left to the address. A host's state is not a label: a drain would start every one of its series over (breaking `rate()` across it and the `for:` of its alerts), and a `state` label would collide with the daemon's own (`briqyard_machines{state}`). The fleet's `/metrics` says it instead, one series per host: `briqyard_fleet_host_state{host, region, state} 1`, kube-state-metrics' node shape.

**The metrics token or the API's opens a scraper's paths,** on the daemon (`/metrics`) and the fleet (`/metrics`, the targets, the relay); no token there on a loopback listener with nothing in front, as before. The metrics token exists so a scraper never holds the API's; refusing the API's on `/metrics` protected nothing (it reads as much through `/v1/status`) and would have made a host with a `metrics_token` unreadable to the fleet, which holds only the host's API token. The metrics token still opens nothing else.

**`briqyard_machines_stopped{reason}` on the daemon:** stopped machines by why (`user`, `idle`, `exit`, `host`), every reason always present. Asleep is `reason="idle"`; `briqyard_machines_suspended` (a memory snapshot kept) is not the same set: a machine stopped on request can keep one, an idle one need not.

**Prometheus and Grafana, optional, installed by `hack/install-monitoring.sh` on the fleet's server.** Pinned releases checked by SHA-256 (Prometheus 3.15.1, Grafana 13.2.5), a systemd unit each as a user of its own, the same shape as the registry mirror's (ADR 0036). Prometheus because the daemon and the fleet already write its exposition format and every tool reads it; Grafana for dashboards and alerts in one process, so no Alertmanager. Neither is required: the fleet and the hosts run the same without them, and an operator with a Prometheus of their own points it at the targets URL.

**Both on loopback; Grafana reached through the operator's reverse proxy,** as the fleet is (TLS, the name, the certificate are the proxy's). Prometheus is not served: Grafana is how a person reads it. Grafana has no anonymous access, no sign-up, no organisation creation, its analytics, update checks, news, gravatars, external snapshots and plugin preinstalls off. The admin password comes on stdin or from a `0600` file, never in argv; Grafana makes its admin at its first start, on loopback, and the script sets the password right after, through `grafana cli … --password-from-stdin`. The script keeps no copy.

**Retention 90 days by default** (`RETENTION`), Prometheus's local storage: a quarter to compare against, about 1 to 2 bytes a sample. A fleet of 10 hosts with 200 machines each (12 series a machine, ADR 0021) is about 25,000 series, 1,700 samples a second at 15 s: about 20 GB for 90 days.

**Dashboards and alerts are files in the repository** (`hack/monitoring/`), provisioned read-only into a `briqyard` folder: a fleet overview, a host, machines and tenants. Every query uses series the daemon and the fleet export; `hack/monitoring-check.sh` runs each against a live Grafana. Alerts, with a Slack webhook in `/etc/briqyard-monitoring/alerting.env` (root's, `0600`, the env file shape of ADR 0041): a target not answering for 2 minutes, a host condition, a pool over 80 %, a machine restarted three times in ten minutes (the daemon's crash loop, named by machine), and the three capacity rules `OPERATIONS.md` gave as Prometheus rules (creates refused for memory or disk, for pressure, a largest slot under `LARGEST_SLOT_MB`).

## Rejected

| Alternative | Why not |
|---|---|
| A UI in the fleet | No history: what is true now is `host ls` and `top` already; a time series store is a project of its own |
| Prometheus scraping the hosts directly, TLS checks off | Anyone on the path is the host; it needs every host's token in Prometheus, a route to the private network, and a target list to edit at each `host add` |
| Prometheus with each host's certificate as its CA | A file per host, written again at each add and each new certificate, for a trust the fleet's pin already gives; still every host's token in Prometheus |
| Static targets, or file discovery written by the fleet | An edit, or a file on Prometheus's disk, per host added; HTTP discovery is the fleet's own answer |
| Alertmanager and Prometheus rules | A third process and a second configuration for what Grafana's alerting does with the dashboards' datasource |
| VictoriaMetrics | Smaller on disk and memory, and it reads the same scrape configuration and answers PromQL: a drop-in when a fleet outgrows a single Prometheus, not needed now |

## Consequences

- Each scrape of a host is a request through the fleet: 15 s × the hosts, each a few kilobytes per machine. A fleet that stops stops the scrapes; the alert says so (the fleet's own target is down too).
- The stack takes about 1.5 GB of disk (Grafana 13.2.5's release alone is 1.3 GB) plus its samples, and about 700 MB of memory: measured in the development VM with two hosts and about 20 machines, Grafana 534 to 604 MB resident, Prometheus 70 MB, 3 MB of samples after 8 minutes. On a server that also runs machines, `capacity.reserved_memory_mb` grows by that.
- Counters start at zero with each daemon (ADR 0021): `increase()` and `rate()` handle the reset.
- Not built: long-term storage, Prometheus served to other tools (point another Prometheus at the targets), alerts other than Slack (Grafana's own contact points do it by hand), a metrics token per host.
