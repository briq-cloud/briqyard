# ADR 0024: Changes at the next boot: a PATCH of the image, command, env, files, size, ports and restart

Date: 2026-10-21 · Status: accepted; amends ADR 0019 (`applied`, `updated` with `pending`)

## Context

A machine's image, command, env, files and size were fixed at create; PATCH took the sleep window, metadata, egress, limits and probes. To change an image or an env var, briq destroyed the briq and made another: a new address, new endpoints, the volume gone unless restored from a backup. Kubernetes changes a pod's container with `kubectl apply` or `set image` (the container restarts on the new image, the PersistentVolume stays) and resizes in place. The scope test (`../KUBERNETES-MAP.md`, Workloads) puts it here.

## Decisions

**PATCH takes the spec**: `image`, `entrypoint`, `cmd`, `env`, `files`, `size`, `ports`, `restart`, each replacing the machine's whole value, as create names them.

```json
{"image": "python:3.13-alpine", "env": {"V": "2"}, "size": {"vcpus": 2, "memory_mb": 1024}}
```

`env` and `files` are write-only, as at create: never in a view or an event. A field set to what the machine has is no change.

**One check for both.** `SpecChange::check` (`briqyard-api`) is what create and PATCH run, so both refuse a bad spec with the same message: an empty image, a size out of range, a file whose path is not absolute, whose base64 does not decode or whose mode is not octal, an env name that is empty or holds `=`, port 0, a restart policy not `no`, `on-failure` or `always`. The CLI runs it before sending.

**Applied at the next start, never to a running process.** The change is kept on the record as `pending` (a second PATCH merges over the first; a field set back to the machine's value drops out). The view shows `pending: {fields, image?, size?, ports?, restart?}` (the write-only fields by name only) and `pending_since`. A running machine runs on unchanged. The next start applies it: a start or a wake after a stop or a sleep, a restart by the policy, and `POST /v1/machines/{id}/restart` (stop, then start; `If-Match` checked by the stop), the caller's way to apply it now. The change goes onto the record in the step that reserves the machine's memory, and the boot reads the record: the config drive (command, env, files), the jail's cgroup and Firecracker's machine config (size).

**A memory snapshot is dropped when the change touches what it holds**: the image, the entrypoint, the command, the env, the files or the size (the guest's memory holds the old process, its env and files; its size is the VM's). That start is cold. `ports` and `restart` are the daemon's alone: a resume applies them.

**A new image is resolved and built before anything moves** (the image cache, ADR 0009). A pull or build that fails is `boot_failed` (409, ADR 0011): the machine in `error` with the reason, the change still pending, so a start tries again and a PATCH can fix it. Then the root disk is made again from the new image's `@base` before the boot; the data volume is not touched (the container image changes, the PersistentVolume stays). The record says which image the root disk was made from (`root_key`): a start whose `image_key` differs makes it again from the image the cache has for the record's reference (pulled again if the host removed it meanwhile), so a start that failed halfway (a host fault after the change was applied) finishes it at the next one. What was written on the old root goes with it: state belongs on the volume, as ADR 0002's boot files rewritten at each cold start already say.

**Forks of the old root take its snapshots over**, as at a destroy (`zfs promote`, ADR 0002), and the fork snapshot the old root came from is freed once nothing clones it. Refusing the change while forks exist is the other rule: it ties a source's image to its forks' lives, and needs the same check at the start (a fork made after the PATCH). Promotion is already the destroy's rule, so it is the simpler correct one.

**A new size is reserved at the start**, by the one-step reservation: past the host's memory it is 503 `capacity` like any start, the change still pending. Through the fleet, placement reserves per create (ADR 0013); a start answering `capacity` is what the provider already retries. A tenant pinned to a full host cannot grow there: the fleet's `unpin`, after backups, is the operator's way to move it.

**Events** (ADR 0019's closed list, now 30): `updated` at the PATCH with `{fields, pending: true}`, the fields whose pending value moved (a change in the same PATCH that applies at once has its own event); `applied` (normal) at the start that applies it, with `fields`, logged before that start's `starting`.

## Consequences

- briq can change a briq's image, env or size with a PATCH and a restart, keeping its address, endpoints and volume.
- A start that pulls holds the machine's lock for the pull, as a create does; its caller waits for it.
- After an image change the root's backup chain starts again with a whole stream; the data volume's goes on.
- `cmd: []` runs the entrypoint alone (Docker's rule, as at create); a PATCH cannot unset a field back to the image's default: it sends the image's value.
- Not built: a change applied to a running process (memory hot-plug, a live env), a rollout across replicas (groups), a volume resize.
