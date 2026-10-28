# ADR 0041: A host's credentials come from an environment file

Date: 2026-10-28 · Status: accepted; amends ADR 0008 (where the store's credentials come from)

## Context

The daemon reads the store's credentials from its environment (`BRIQYARD_S3_ACCESS_KEY`, `BRIQYARD_S3_SECRET_KEY`; ADR 0008, 0034), but the unit `hack/bootstrap-host.sh` writes gave it no way to get them. The fleet's unit has one (`EnvironmentFile=-/etc/briqyard/fleet.env`); the daemon's had none, so a host with a store needed a systemd drop-in written by hand. Kubernetes does this the same way: kubeadm's kubelet unit reads `EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env` and `/etc/default/kubelet`, and whatever manages the node writes them.

## Decisions

**The daemon's unit reads `EnvironmentFile=-/etc/briqyard/briqyardd.env`**: root's, `0600`, optional (`-`: a host with no store starts without it). The same shape as the fleet's.

**briqyard reads it and never writes it.** The operator's tooling does (a secrets workflow, a configuration manager, an editor). The bootstrap leaves it alone, so a bootstrap run again or an upgrade keeps it.

**A change is read at the next start: a hand-over, never a restart.** `systemctl restart` suspends every machine; the hand-over of ADR 0027 leaves them running:

```bash
systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd   # exits, machines left running
# wait until MainPID changes (the bootstrap waits up to 120 s), then:
systemctl start briqyardd                                    # adopts them, with the new environment
```

## Consequences

- A host gets the line at its next bootstrap. Through a fleet, that is a release of the fleet with this script (`bootstrap.rs` embeds it), then `host upgrade`. Before that, a drop-in with the same line does the same.
- The dev VM's unit (`hack/briqyardd.service`, installed by `hack/vm.sh`) carries the same line, so a VM install and a bootstrap write the same unit.
