# ADR 0050: No restart or reboot outside a planned upgrade

Date: 2026-10-29 · Status: accepted; complements ADR 0027 (the hand-over)

## Context

Hosts run Ubuntu 26.04 with unattended upgrades on (`APT::Periodic::Unattended-Upgrade "1"` in `/etc/apt/apt.conf.d/20auto-upgrades`) and `needrestart` installed (3.11-1ubuntu2). `briqyardd` and `briqyard-fleet` are linked against glibc and OpenSSL, so a security update of either leaves them mapping a deleted library.

Since Ubuntu 24.04, apt's hook runs needrestart in an Ubuntu mode (`apt-pinvoke -m u`, `/etc/apt/apt.conf.d/99needrestart`): restart mode `a`, services restarted without asking, with or without a terminal ([Ubuntu's announcement](https://discourse.ubuntu.com/t/needrestart-changes-in-ubuntu-24-04-service-restarts/44671), [the `ubuntu-mode` patch](https://git.launchpad.net/ubuntu/+source/needrestart/tree/debian/patches/ubuntu-mode.patch?h=ubuntu/devel)). Upstream falls back to listing when there is no terminal; Ubuntu does not. Setting `$nrconf{restart}` or `$nrconf{ui}` turns the Ubuntu mode off for every service ([LP #2068543](https://bugs.launchpad.net/ubuntu/+source/needrestart/+bug/2068543)). A service is skipped only through `$nrconf{override_rc}` (Ubuntu ships `keepalived` and `glusterd` entries for the same reason).

Checked in an Ubuntu 26.04 container with systemd: three units preloading a library, the library replaced, then `apt-pinvoke -m u` with no terminal, as apt runs it. Without an override, `systemctl restart briqyard-fleet.service briqyardd.service other.service`, all three new PIDs. With the override below, `other.service` restarted, both briqyard units listed under "Service restarts being deferred", same PIDs.

A `systemctl restart briqyardd` is not a hand-over: it suspends every machine and boots them again (`OPERATIONS.md`, Upgrade), and an update window can hit every host at once. The bootstrap's own `apt-get install` runs the same hook, on a host whose daemon is running, before the hand-over.

## Decisions

**The bootstrap writes `/etc/needrestart/conf.d/briqyard.conf`** on every host, before its `apt-get install`; needrestart installed later reads it too:

```perl
$nrconf{override_rc}{qr(^briqyardd\.service$)} = 0;
$nrconf{override_rc}{qr(^briqyard-fleet\.service$)} = 0;
```

Only `override_rc`: the Ubuntu mode stays on for every other service. A fleet on a server without a host gets the same file by hand (`OPERATIONS.md`, A fleet).

**The host never reboots itself.** `Unattended-Upgrade::Automatic-Reboot` is false by default (commented out in `50unattended-upgrades`); the bootstrap does not set it, and a reboot stays a drain first (`OPERATIONS.md`, Upgrade). needrestart's Ubuntu mode only prints a pending kernel.

**`briqyard doctor` warns** (`warn`, not `MISS`: the host works) when needrestart is installed and the last `override_rc` entry matching `briqyardd.service` (its file, then `conf.d` in name order) is not 0, and when `apt-config` says `Automatic-Reboot` is true.

## Consequences

- A security update lands on disk; the daemon and the fleet run the old library until their next `host upgrade` (the same release again is fine) or reboot. Applying it is the operator's planned step, as for the kernel.
- A host gets the file at its next bootstrap: through a fleet, a release of the fleet with this script (`bootstrap.rs` embeds it), then `host upgrade`.
- Reopen if needrestart learns to call something other than `systemctl restart` that a unit could map to a hand-over.
