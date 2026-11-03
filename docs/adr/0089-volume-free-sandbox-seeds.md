# ADR 0089: Volume-free sandbox seeds

2026-11-03 · Proposed; native qualification required before enablement

## Context

A sandbox seed (ADR 0076) and the unbound warm slots made from it (ADR 0077) carry a third
Firecracker drive, `data` (`/dev/vdc`), saved in the memory snapshot. Only a create with a
`/work` volume of exactly the recipe's `volume_gb` could claim one. A create without a volume
cold-booted: about 590 ms at host level, against 320 ms from a named template and 101 ms from
a ready slot. Not every sandbox needs a data disk, and the drive cannot be added to or removed
from a sealed snapshot, so the topology has to be a property of the seed.

## Decisions

**A recipe may declare no data volume: `volume_gb: 0`.** The field stays required, so a
forgotten field is a refused config, never read as volume-free. Existing recipes, with a
positive `volume_gb`, load and behave as before. A recipe is identified by image, size,
init digest and volume; one image and size may be approved in both shapes at once.

**The data drive is part of the seed's identity.** `Config.sandbox_device` already sits in the
sealed artifact's recipe config, so the artifact fingerprint, the warm pool fingerprint and the
selector key include it. A volume-free builder has `volume: None`, a config drive without
`sandbox_device`, and a seal with two drives (`rootfs`, `config`). No new artifact field.

**In the guest, no `sandbox_device` means no `/dev/vdc`.** Init still quarantines the device
when there is one. With none it fails the boot (builder) or the bind (destination) if
`/sys/class/block/vdc` exists. `DestinationBind::validate` accepts exactly two shapes: a
`sandbox_device` with one ext4 `/dev/vdc` mount at `/work`, or no device and no mounts. The
host sends the device it expects and the guest checks the hardware against it, so a
disagreement between host record and drives fails closed in the guest too.

**The request names the shape; nothing is adapted.**

| Request `volume` | Seed with `/work` of N GiB | Volume-free seed |
|---|---|---|
| none | refused | served |
| `/work`, N GiB | served | refused |
| other size or mount | refused | refused |

`check_sandbox_seed` requires `/work` and a positive size only when a volume is given. The
daemon looks the recipe up by the request's volume, then compares the seed's sealed device with
the recipe's, so a volume request for an existing size cannot reach a volume-free seed. A
refusal is an invalid request, as today. The generation check refuses a seed of another
generation (ADR 0087) and the shape check refuses after it; neither falls back to a cold create.

**A builder names its volume as a create does.** `template_build: sandbox-ready-v1` may carry
`volume: {size_gb, mount: "/work"}`; without one it builds the volume-free shape. This replaces
"the recipe fills the volume in": with two shapes per image and size the request has to pick,
and the same rule everywhere is simpler than a rule for builders only. A builder request that
omitted the volume for a recipe with one is now refused (not approved) rather than given the
recipe's volume. Seeds are disabled by default and none is deployed, so nothing is migrated.

**Unbound pools key on the full profile.** The factory reads the shape from the pool's
artifact and makes slots with that volume or none. A slot's record volume must equal its sealed
device (`prepare_unbound_warm_slot`), and assignment keeps comparing the request's volume with
the slot's, so a volume-free slot serves only a volume-free create. Data-volume liability is
zero for such a slot; the positive `data_disk_gb` budget that enabling unbound pools still
requires is unchanged here.

**An assigned machine's run follows its record's volume.** The run journal (`Current`, `Reader`,
`Checkpoint`) holds `data: Option<Disk>`, set from `record.volume` as the ordinary start does, and
the continuation boots with a data drive only when the record has a volume. A volume-free
assigned machine stops and starts like any other. Journals written with a data disk read as before.

## Alternatives

- **`volume_gb: Option<u32>`, absent for none.** A forgotten field would silently change a
  recipe's shape. A required `0` is explicit and needs no wire change.
- **A third profile string (`sandbox-ready-v1-novolume`).** Every profile check, the pool
  selectors and the guest gate would grow a branch; the profile does not change, its topology does.
- **Attach an empty volume and hide it from the guest.** Costs a disk, a mkfs and a charge for
  something the workload never sees.
- **Let any create claim any seed and adapt the drives.** A Firecracker snapshot cannot lose or
  gain a drive; mismatches must be refused.

## Consequences

- Existing recipes need no change (a positive `volume_gb` keeps its meaning). Seeds are re-sealed
  with the release because init's digest changes (ADR 0087), not because of this ADR.
- Records of volume-free machines carry `Binding.device: null` and `data: null` in run journals, which
  a previous-release daemon fails to load at startup. Acceptable while no seed is deployed.
- A volume-free seed is a new artifact: the operator builds and seals it once per image and
  size, in addition to the volume seed, and raises the pool catalog by one entry.
- Capacity: a volume-free slot holds a root disk and memory, no data disk.
- No openapi schema changes; `sandbox_seed` documentation says the volume is optional.
- Interaction with ADR 0087 (boot identity schema 2, `Mount.read_only`, a create naming a seed of
  another generation refused): orthogonal. This ADR changes the recipe and the drive topology;
  that one changes the boot identity and the generation outcome. Both go in one release with one
  seed re-qualification. The device comparison here runs after the generation comparison; a stale
  generation is refused first, and a shape mismatch is refused after it, with no cold fallback in
  either case.

## Tests

Config parsing (old config unchanged, `0`, missing field, coexisting shapes, duplicates),
`check_sandbox_seed`, `DestinationBind` validation, the volume matrix above on a real seal and
on a pool, a volume-free builder (record, config drive, artifact), builder volume refusals,
clone-spec topology, factory slot and pool fingerprint, assignment and recovery of a
volume-free slot, a volume-free assigned machine's stop and start, and the guest's absent-drive check. Native Linux still has to run: a
volume-free seal and clone in Firecracker, boot with two drives, `/work` absent after bind,
the init's sysfs check, and the ready-slot timing for the new shape.
