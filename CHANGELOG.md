# Changelog

## 0.2.7 — 2026-11-11

### Upgrade notes

- The heartbeat carries each host's boot admission (`boots_at_once`, `boot_queue`) and a placement can answer the new `busy` outcome with a queue `depth` (ADR 0130). Roll the fleet before the hosts so it reads the new heartbeat; an older fleet ignores the fields.
- The fleet advertises `placement_spill_v1: true` in `GET /v1/status`. A placement admission with `spill_when_busy: true` passes over a region whose boot queue is at least `placement.spill_waves` (default 2) deep. An older fleet answers 400 to the flag, so a control plane must check the capability first and resend without the flag on a 400.
- Rolling the fleet back below 0.2.7 cannot load a placement record whose outcome is `busy`: roll back only when no such admission is pending and its tombstones have been pruned (two windows, 48 hours).
- The guest init is unchanged from 0.2.6, so its digest is too (ADR 0101): seeds need no resealing.

### Documentation

- spill a burst to the next allowed region when boots queue (#232) ([b35ffb5a](https://github.com/briq-cloud/briqyard/commit/b35ffb5a4ca2ec22538ae3cceeb94ba4bae25c45))


### Features

- boot queue in the heartbeat (ADR 0130 phase 1) (#233) ([6bb4ced8](https://github.com/briq-cloud/briqyard/commit/6bb4ced8eb9db54a9fd0d9282fdd651904b3ebd0))

- spill a burst to a later region when the first is busy (#234) ([94c99f0a](https://github.com/briq-cloud/briqyard/commit/94c99f0ae8663fef3ef3c41fa4544c9125bd0bcd))

## 0.2.6 — 2026-11-11

### Upgrade notes

- v0.2.5 was never published, so 0.2.6 is the first release with placement admission: the fleet advertises `placement_admission_v1: true` in `GET /v1/status` and answers the new placement admission route (ADR 0128). An older fleet answers 404 to it, which is never capacity, so a control plane that offers a region preference must require 0.2.6 first. Rolling the fleet back below 0.2.6 reads placement records as seed admissions; roll back only when no placement admission is pending and the tombstones have been pruned. See "Rollback" under "Placement admission across regions" in `docs/FLEET-OPERATIONS.md`.
- Also first published here: `boots_at_once` defaults to one and a half times the hardware threads, at least 2 (ADR 0129); an explicit value still wins.
- The guest init's code changed from 0.2.4 (service-ready loaded templates, #219, and the follow-ups in #222), so its digest changes (ADR 0101). Existing seeds and running guests keep the init they were sealed with. Seeds sealed against an older init need resealing: compare the candidate's `SHA256SUMS` line for `briqyard-init-linux-<arch>` first. `templates.service_ready` stays off by default and needs the exact init digest.
- With `templates.service_ready` on, #222 closes the exec admission race at park: park waits (at most 5 s) for already admitted executions to spawn, the hook's process group is killed and reaped before the checks, and a refusal whose thaw is not confirmed within 10 s answers `park_unrecoverable` and stops the source (ADR 0127). No change while the flag is off.

### Fixes

- fleet: the placement admission hold defaults to 4 minutes (was 10)
- service-template follow-ups from #220 (#222) ([d3cf502a](https://github.com/briq-cloud/briqyard/commit/d3cf502af1d3bba26264b63977a63c8433278b0d))

## 0.2.5 — 2026-11-11

### Upgrade notes

- The fleet advertises `placement_admission_v1: true` in `GET /v1/status` and answers the new placement admission route (ADR 0128). An older fleet answers 404 to it, which is never capacity, so a control plane that offers a region preference must require 0.2.5 first. It asks once before any host is asked to create anything.
- Rolling the fleet back below 0.2.5 reads placement records as seed admissions: a `cold` record fences nothing, a pending `sandbox-seed` record fences its namespace and host and is never forgotten, and an `expired` tombstone cannot be loaded. Roll back only when no placement admission is pending and the tombstones have been pruned (two windows, 48 hours). See "Rollback" under "Placement admission across regions" in `docs/FLEET-OPERATIONS.md`.
- The guest init's code changes (service-ready loaded templates, #219), so its digest changes from 0.2.4 (ADR 0101). Existing seeds and running guests keep the init they were sealed with. Compare the candidate's `SHA256SUMS` line for `briqyard-init-linux-<arch>` and reseal seeds before turning on `templates.service_ready`, which stays off by default and needs the exact init digest.
- `boots_at_once` now defaults to one and a half times the hardware threads, at least 2 (ADR 0129); an explicit value still wins.

### Documentation

- placement admission across an ordered list of regions (#221) ([0da5e716](https://github.com/briq-cloud/briqyard/commit/0da5e71618c1977fba5414fe02fab8c5e8be9fef))


### Features

- service-ready loaded templates behind a default-off flag (#219) ([0e5e9b12](https://github.com/briq-cloud/briqyard/commit/0e5e9b12cc3c43b13b88da48d940ae83fe7225d6))

- placement admission across an ordered list of regions (ADR 0128) (#224) ([74865581](https://github.com/briq-cloud/briqyard/commit/7486558163303a97403f6a281e9d81a598093968))


### Performance

- boot 1.5 × the hardware threads at once by default (#223) ([f4380409](https://github.com/briq-cloud/briqyard/commit/f4380409b5f59482f466e562d178b2afa74f12b5))

## 0.2.4 — 2026-11-10

### Upgrade notes

- Stopped updates accept an optional `probes` object that atomically replaces the stopped machine's probes with its image and environment; an empty object clears them, and omission preserves them. Older hosts refuse the field as unknown, so callers must require 0.2.4 before sending it.
- `FileRequest` v1 commitments are defined but dormant: no routes, grants, admission or guest-protocol changes are active.

### Features

- define scoped file request commitments (#215) ([90ae6bce](https://github.com/briq-cloud/briqyard/commit/90ae6bcef67ce22d0a59be0cfd5bcde3c4dc7916))

- atomically replace probes in stopped updates (#216) ([e703de67](https://github.com/briq-cloud/briqyard/commit/e703de6763684cd4b7b8df9c6b9d13282fbf80e8))

### Fixes

- verify streamed upload acknowledgements against the host-computed byte count and SHA-256 (#214) ([1f7db636](https://github.com/briq-cloud/briqyard/commit/1f7db63674364a996f6da767a5f7d146b5536905))

## 0.2.3 — 2026-11-10

### Upgrade notes

- Scoped listeners remain disabled without explicit authenticated provisioning. Their durable journals bind ownership, delegation versions, immutable projections and one-shot admissions; uncertain operations recover through status without dispatch replay.
- Opening scoped host state establishes permanent `scoped-execution-v1` / schema 5 compatibility authority. Renewable operations require `scoped-execution-v2` / schema 6. Older binaries must not open retained scoped state; managed handover and rollback enforce these requirements.
- The guest init changes to support renewable execution. Compare the candidate's exact `SHA256SUMS` and reseal seeds with the new init before using that capability. Existing running guests retain their original init and execution capabilities.

### Features

- add durable scoped command channel (#206) ([e503c6bf](https://github.com/briq-cloud/briqyard/commit/e503c6bf0f14f5ad3b2240c160d7d85bcc02a94a))

- bind immutable projections and renewal versions (#208) ([9f4a2470](https://github.com/briq-cloud/briqyard/commit/9f4a24704706e5fc150a9aac7e3d2e5fa0131b78))

- expose authenticated live installation identity (#209) ([2faf6f2b](https://github.com/briq-cloud/briqyard/commit/2faf6f2bf2a0c80fb86fb617013f5f30932a1ae3))

- provision isolated authenticated runtime listeners (#210) ([4023b3ff](https://github.com/briq-cloud/briqyard/commit/4023b3fffe5e4188a8640fea0ba03bb91c82dc33))

- add dormant renewable operation continuation (#211) ([42e965a5](https://github.com/briq-cloud/briqyard/commit/42e965a5fabf7d0078ad2206cdd2dce10d06ea93))

### Fixes

- Apply clock uncertainty once per scoped command deadline check. Retain the signed wall expiry separately from the initial monotonic cap, preventing premature quiet-command termination without extending authorization.

## 0.2.2 — 2026-11-09

### Upgrade notes

- Image-created machines use stopped-update receipts; assigned machines keep their existing lifecycle. The init digest is expected to remain unchanged (ADR 0101): no init source or dependency changed. Confirm the exact candidate's init digests in `SHA256SUMS` before reusing sealed seeds.

### Features

- `POST /v1/machines/{id}/stopped-update` records the complete cold image and environment target after compare-and-swap and VMM exit. Exact-nonce `GET` recovers the receipt without replaying the POST ([757de264](https://github.com/briq-cloud/briqyard/commit/757de2648b0c3ee66f38fbcc45d552691b90d8f3)).

### Fixes

- Preserve accepted targets and nonce reservations after directory-sync failure; establish durability before later writes or lifecycle effects ([80ae1b55](https://github.com/briq-cloud/briqyard/commit/80ae1b5509dedc07cb7389f9f5747deab8f2abd3)).

### Maintenance

- Verify native unbound claim and refill (#202) ([f3c21764](https://github.com/briq-cloud/briqyard/commit/f3c21764846d8985911a2756263dcf27f3fb4878)).
## 0.2.1 — 2026-11-09

### Upgrade notes

- Initial assigned machines accept live volume growth and stopped complete boot-file replacements (ADR 0125). Schema 3 update journals require `assigned-update-v3` and permanent protocol floor 4; rollback must support retained authority.
- The init's digest is expected not to change (ADR 0101): no init source or dependency changed. Confirm the exact candidate's init digests in `SHA256SUMS` before reusing sealed seeds.

### Fixes

- Ordinary stopped image, environment and volume changes require positive VMM exit before any part of the update moves. Missing or unsettled launch proof, a nonzero pid or an unexited live handle refuses the update; effective no-ops remain no-ops. Snapshot-affecting changes boot fresh at the next start (ADR 0024).

### Tests

- Extend artifact-backed upgrade qualification with retained-set rollback refusal and candidate restoration, plus aged template siblings checked for guest clock, network identity and separate vsock execution. Native qualification remains pending execution.

## 0.2.0 — 2026-11-09

### Upgrade notes

- Stopped assigned machines accept image and complete environment updates, including before the first continuation (ADR 0080). An empty environment clears it; omission retains the pending environment. The next start consumes the update and boots cold. Schema 2 creation-update authority requires this release; a rollback must support any durable update authority still present.
- Initial running assignments accept DATA-volume growth before their first continuation; stopped assignments accept complete boot-file replacement (`[]` clears it, omission preserves pending files). These updates use schema 3, the `assigned-update-v3` capability and permanent protocol floor 4. Managed installation, handover and automatic rollback reject weaker binaries; schema 1/2 journals retain their existing bytes and validation (ADR 0125). Clearing boot files does not delete paths previously written in the guest.
- **Breaking:** SIGUSR2 now checks the same conservative warm-catalog predicate as `briqyard warm-maintenance`, under exclusive warm then namespace admission retained through exit. Compatible replacement capabilities alone no longer permit handover with outstanding warm ownership, including healthy assigned workloads. Settle ownership through its normal lifecycle; the check never drains workloads. The daemon being replaced must implement this guard, so it cannot protect the first upgrade from an older daemon.
- Pools with nonzero desired capacity, outstanding claims, warm machines, holds, transitions, pending assignments and unsettled run authority refuse maintenance. Valid historical claim receipts whose destinations are absent from both live and durable machines, and settled run histories with matching durable machine/reference and reader links, remain valid history. Malformed, inaccessible, inconsistent or over-budget state refuses without repair or cleanup. An eligible observation is not a handover permit.
- Native handover, workload continuity, warm auto-claim/refill and recovery qualification remain open. Init digest continuity and any need to reseal seeds remain pending `hack/init-digest-check.sh` and comparison of the exact candidate's init digests in `SHA256SUMS` (ADR 0101).

### Features

- Define version-one scoped execution grant, allocation and permit types with optional Ed25519 verification. No daemon or fleet route accepts these credentials; administrator authentication is unchanged (#196, ADR 0120) ([0847399e](https://github.com/briq-cloud/briqyard/commit/0847399ed4cc4a3520ee9993e44c66dd43ad3b30)).
- Add durable scoped-execution issuer and host admission, with atomic quota debits, consumed admission receipts, frozen run identity and bounded guest access (#199, ADR 0124). Scoped HTTP access remains unavailable; administrator routes keep their existing authentication and behavior ([c37d21dd](https://github.com/briq-cloud/briqyard/commit/c37d21dd49be572f90b354fea0bd00a0e4614566)).
- Retain the validated configuration input identity. `briqyardd --config PATH check-config` uses the same parser and validation and returns only that identity, or `configuration_invalid`, without opening host state. Defaults have a distinct identity; constructed configurations are unobserved (ADR 0121).
- Observe an exact sealed snapshot through authenticated `GET /v1/machines/{id}/snapshots/{snap}/sandbox-recipe`, including on loopback. The source lifecycle lock and existing provenance checks validate its recipe and runtime/configuration identity; observation creates no reservation or authorization (ADR 0122).
- **Breaking:** Add authenticated `GET /v1/maintenance/warm-catalog`, the `briqyard warm-maintenance` command and the shared SIGUSR2 handover guard (#197, ADR 0123) ([4f713342](https://github.com/briq-cloud/briqyard/commit/4f7133427ebd4f8325c67342f0a9bb1ffb6ec4a0)).

### Fixes

- A record deleted during a store listing is not an error (#195) ([c07f068a](https://github.com/briq-cloud/briqyard/commit/c07f068ab16f41246e1ee1da47219db152dad2b1)).
- Support stopped assigned image and complete environment updates, including an initial assignment before its first continuation (#198, ADR 0080) ([c1942295](https://github.com/briq-cloud/briqyard/commit/c194229582f6e982022c790adce31dc0de9e8626)).
- Preserve original process authority during initial assigned volume growth and stopped boot-file updates (#204, ADR 0125) ([3d75053b](https://github.com/briq-cloud/briqyard/commit/3d75053be23669169a0e3357f2ff757cf014ec0d)).

## 0.1.33 — 2026-11-08

### Upgrade notes

- The init's digest is expected not to change with this release (ADR 0101): no init source or dependency it uses changed. Confirm it in the candidate's `SHA256SUMS`: seeds sealed under v0.1.28 stay valid.
- The fleet forgets settled records (ADR 0119): accepted sandbox routes and settled admissions 24 hours after they settle, namespace versions once their namespace is pinned nowhere and nothing unsettled names it, pin times once their namespace is pinned nowhere. It prunes at start and on every heartbeat. Unaccepted routes and pending seed admissions are never pruned. A registry written by an earlier fleet has no times on these records: at the first start, the records of namespaces pinned nowhere go at once and the rest a day later, so the registry shrinks in two steps after the upgrade.
- A save that finds nothing changed since the last write no longer encodes the registry, and callers that waited behind a write share the next one.

### Performance

- bound the registry and skip saves that find nothing new (#193) ([27717f51](https://github.com/briq-cloud/briqyard/commit/27717f51ed521c23ecd0f8f8df9294a6196ce7e5))

## 0.1.32 — 2026-11-08

### Upgrade notes

- The init's digest is expected not to change with this release (ADR 0101): no init source or dependency it uses changed. Confirm it in the candidate's `SHA256SUMS`: seeds sealed under v0.1.28 stay valid.
- Namespaces are made in parallel (ADR 0118): only the choice and reservation of a subnet index stay under `namespace_create`; the bridge, the DNS listener and the record are done outside it, once per namespace. No action is needed. A namespace rename still holds the lock while it waits for its machine to stop.
- The fleet logs one `warn` line with the code and message of every 5xx it answers itself, and the host of every 5xx it relays.

### Fixes

- log the cause of every 5xx the fleet answers (#189) ([4763719b](https://github.com/briq-cloud/briqyard/commit/4763719bf6b82dd95e642a0541b796666fadc38e))


### Performance

- make namespaces in parallel (#190) ([6c20d10b](https://github.com/briq-cloud/briqyard/commit/6c20d10bb1e653c4bcd21f5a7192199ab40ab25c))

## 0.1.31 — 2026-11-07

### Upgrade notes

- The init's digest is expected not to change with this release (ADR 0101): no init source or dependency it uses changed. Confirm it in the candidate's `SHA256SUMS`: seeds sealed under v0.1.28 stay valid.
- Creates from a seed now overlap in their record step (ADR 0117): the warm and sandbox locks are shared unless a ready warm slot may serve the create. No action is needed. Under a continuous burst of seed creates, the warm refill tick skips and `fail_fast` claims answer pool-empty until there is a gap.

### Documentation

- cover a hung daemon and name the monitoring units (#186) ([acfe42ff](https://github.com/briq-cloud/briqyard/commit/acfe42ff6723aefd7208add7aed9d4ee2dce75c9))


### Performance

- seed creates record concurrently (#187) ([9a4ca9af](https://github.com/briq-cloud/briqyard/commit/9a4ca9afdd5cedb3cb81f61328a8b25f4a042e9c))

## 0.1.30 — 2026-11-06

### Upgrade notes

- The init's digest is expected not to change with this release (ADR 0101): no init source or dependency it uses changed, and `briqyard-api` gained only console-log types the init does not use. Confirm it in the candidate's `SHA256SUMS` line for `briqyard-init-linux-<arch>` against v0.1.29's (`365e5d1b…` on x86_64); if it differs, seeds are sealed again as `docs/OPERATIONS.md` (Upgrade) says.
- The console log API changes (ADR 0115, ADR 0116). `GET /v1/machines/{id}/logs` answers the newest lines of the app view by default: kernel and `[briqyard]` runtime lines leave it, and `view=runtime` returns them (`--view runtime` in the CLI). A page answers `{lines, before, after, hasOlder, hasNewer}`: the `next` field is replaced by the `before` and `after` cursors, and `limit` defaults to 200 (at most 1000). `since` now belongs to a follow only: on a page it is `400 invalid`. A caller that pages with `since`, reads `next`, expects the start of the console by default, or greps runtime lines in the default view must change. A machine booted by an older daemon keeps a mixed console until its next boot.
- Cloning a named snapshot no longer holds the seed's lock for the clone: creates from one seed run their clones in parallel. No action is needed.
- Sealed seeds stay usable after a reboot on the same kernel: recovery and start no longer compare the artifact's device number, which ZFS changes at each mount. Existing manifests are expected to verify at the next daemon start, with no reseal; the tests cover this with a changed device number, not yet a real host reboot. A reboot that changes the kernel release, the Firecracker or kernel binary, or the init digest still refuses the seed, by design: reseal after such an upgrade. A file-level restore (rsync, tar) changes the inode and is refused too (`zfs send/receive` keeps it), and a seed whose builder runs an older guest init still fails at restart (`template_builder_ready`).

### Documentation

- ADR 0113 assumes one host for the fleet and the edge (#183) ([fd628841](https://github.com/briq-cloud/briqyard/commit/fd6288412004c14c4cc3e25d481512775c1f94ea))


### Features

- page the console from the tail with before and after cursors (#182) ([ee4da888](https://github.com/briq-cloud/briqyard/commit/ee4da888a1d1e51730e51b3c86b92207147303a6))


### Fixes

- separate app and runtime console output at capture (#179) ([ce421728](https://github.com/briq-cloud/briqyard/commit/ce421728ecfbb0608d1e3c8a46ac7d643217494e))

- keep sealed seeds usable after a reboot (#185) ([34d42fc2](https://github.com/briq-cloud/briqyard/commit/34d42fc2bbde7719ca79f852e5c5e5be7ebe9f36))


### Performance

- clone a named snapshot outside the seed's lock (#181) ([1989dbad](https://github.com/briq-cloud/briqyard/commit/1989dbad4a0ebb2a5d8ec1fef2300af7db7ab8e4))

## 0.1.29 — 2026-11-06

### Upgrade notes

- The init's digest does not change with this release (ADR 0101): seeds sealed under v0.1.28 stay valid. A host coming from before v0.1.28 still follows that release's note.
- A listing without `partial=true` behaves as before; a caller opts in (ADR 0114). No action is needed.

### Features

- list machines partially when the caller asks (#178) ([c711186d](https://github.com/briq-cloud/briqyard/commit/c711186db52a833c18b742a96402089bf9f01976))

## 0.1.28 — 2026-11-05

### Upgrade notes

- The init's digest changes with this release: #176 changes the release profile of `sha2`, which the init uses (ADR 0101). Behaviour does not change. Every seed sealed before it is refused until it is sealed again, in the order `docs/OPERATIONS.md` gives (Upgrade). Before the host upgrades, set each recipe's `init_sha256`, and `templates.init_ready_init_sha256` if the configuration has it, to the digest in the `briqyard-init-linux-<arch>` line of `SHA256SUMS`: with only old values the host reports no named-memory profile after its upgrade.
- A host on a private network gets what it got before; WireGuard applies only to the hosts in `bootstrap.wireguard.hosts` (ADR 0113). A bootstrap now retries a pool-key request that fails transiently, up to three times. The fleet writes `published-keys.json` in its state directory. None of these needs an action.

### Features

- join the host plane over WireGuard when a server has no private network (#173) ([a7fb3331](https://github.com/briq-cloud/briqyard/commit/a7fb333151ee949757a461bff4a8f56040156df3))


### Fixes

- check the files the configuration names (#174) ([d1fbe120](https://github.com/briq-cloud/briqyard/commit/d1fbe1202c9eaf066503450fc8be95e81fbfea16))

- a pool key the store acknowledged survives a fleet restart (#175) ([2a0fd24e](https://github.com/briq-cloud/briqyard/commit/2a0fd24e1f35c7ce188190e149f11f34511055d3))


### Performance

- optimize sha2 for speed in release builds (#176) ([fa01fa59](https://github.com/briq-cloud/briqyard/commit/fa01fa5910b773e1ecaa6b20bae586ac31277dc3))

## 0.1.27 — 2026-11-05

### Documentation

- record the nested suites at 8 vCPUs, alerts and qualification included (#169) ([3bcedea3](https://github.com/briq-cloud/briqyard/commit/3bcedea3546c3209fd52377a08506b40d29e75ee))


### Fixes

- serve before sweeping idle cgroups (#153) ([aa0df9d9](https://github.com/briq-cloud/briqyard/commit/aa0df9d9a176632b98ac968b651e864f109c5ef7))

- spawn host helpers through choom so std uses posix_spawn (#168) ([ffd995b8](https://github.com/briq-cloud/briqyard/commit/ffd995b8cfdf3010439bf71ebf262ba19840b760))


### Maintenance

- test the upgrade from the previous release on a host with history (#152) ([05a49b3c](https://github.com/briq-cloud/briqyard/commit/05a49b3c682d6f93e38287123ec36423aba8ff7b))

## 0.1.26 — 2026-11-05

### Fixes

- a temp directory named with "ok" does not fail the bootstrap test (#163) ([f602f3cd](https://github.com/briq-cloud/briqyard/commit/f602f3cd1e374fe564826cb055ddbfb85053e7c9))

- do not write a registry version for every heartbeat (#166) ([f80bc4a7](https://github.com/briq-cloud/briqyard/commit/f80bc4a7017965a40ae15aadf72c8e8db5cc4384))


### Maintenance

- build once per cache, skip native on drafts (#160) ([82d9007d](https://github.com/briq-cloud/briqyard/commit/82d9007da77bd5266164b0d71924e329192eb923))

- run scale on its own runner, 200 idle leaves in the e2e hand-over (#161) ([d46c2e2a](https://github.com/briq-cloud/briqyard/commit/d46c2e2a65dfd5e282fae9217442b75365bf8327))

- run alerts and monitoring only when something they read changed (#162) ([e118ef60](https://github.com/briq-cloud/briqyard/commit/e118ef600e3b951f8ab7f10a8df067960efbf654))

- a stalled mirror does not hold up two-hosts; record the measured times (#165) ([1d3e76c7](https://github.com/briq-cloud/briqyard/commit/1d3e76c7a0f0bce49be928535cda1adca5de9697))

## 0.1.25 — 2026-11-04

### Features

- report each host's disk in the host listing (#156) ([fce11c0a](https://github.com/briq-cloud/briqyard/commit/fce11c0a8a994311e8eaf4c5d93092a01f5239de))


### Fixes

- a full disk is not an unreported one (#157) ([fcd83d20](https://github.com/briq-cloud/briqyard/commit/fcd83d20d0a311ea40fadc952a7d96015d01a2b2))

- a changed webhook reaches Grafana (#158) ([3f768288](https://github.com/briq-cloud/briqyard/commit/3f768288d5382a2c3e19d3941cc142408b800918))

## 0.1.24 — 2026-11-04

### Documentation

- record the ruleset that protects main (#151) ([4e456aa8](https://github.com/briq-cloud/briqyard/commit/4e456aa8d44de2ad099da06d35a87cc06577c5d4))


### Fixes

- a backup's missing key is a typed error, not a 500 with the fleet's address (#150) ([9ac0a2e2](https://github.com/briq-cloud/briqyard/commit/9ac0a2e29796ad18cec8203d265fea22a9d12772))

- count a host's capacity refusals (#154) ([5d33f6d3](https://github.com/briq-cloud/briqyard/commit/5d33f6d3ca77e863abdd1426e530e02d37112ced))


### Maintenance

- stop the daemon before making known machines' leaves (#149) ([22ca2593](https://github.com/briq-cloud/briqyard/commit/22ca2593fc31ac5fdd61b3923849ec1a337e0d06))

- qualify restore with a real workload (#147) ([b4923ea1](https://github.com/briq-cloud/briqyard/commit/b4923ea187117b12bb18f10fc1a19c23ec136d5e))

## 0.1.23 — 2026-11-04

### Upgrade notes

- The init is unchanged from 0.1.21 (ADR 0101): seeds are not sealed again. Confirm it against the `briqyard-init-linux-<arch>` line of `SHA256SUMS`.
- A clean start is unaffected. A start that finds a helper left by a crashed daemon waits up to 10 s for it, before inventory (ADR 0102). If a member stays, the host still refuses placement with `recovery_unresolved`, naming its pid, exe and state, and running machines keep serving; when the member goes, the daemon exits so that systemd runs the whole barrier again. A helper stuck in the kernel needs an operator: `docs/OPERATIONS.md`.

### Fixes

- a helper left by a crashed daemon does not refuse the host (#145) ([b64fcb14](https://github.com/briq-cloud/briqyard/commit/b64fcb1425fc3679cc17a739384d94732b51045a))

## 0.1.22 — 2026-11-04

### Upgrade notes

- The init is unchanged from 0.1.21 (ADR 0101): seeds are not sealed again. Confirm it against the `briqyard-init-linux-<arch>` line of `SHA256SUMS`.
- The `consistency` value `crash` is now `unsynced`, in requests, responses and metric labels. Records already stored keep loading and read as `unsynced`; a request that sends `crash` gets a 400.
- The first start after upgrading from a release before 0.1.20 sweeps its leftover cgroup leaves: linear, about 50 ms a leaf, up to 5 minutes observed. The API and in-process ingress are down meanwhile; machines keep running. A host that already ran 0.1.20 or later has paid this.

### Documentation

- make AGENTS.md the canonical agent guidance (#141) ([bc30466a](https://github.com/briq-cloud/briqyard/commit/bc30466a820e152240331fbcaff0e757166f018a))


### Fixes

- remove a VMM's cgroup leaf when it goes (#139) ([f75f0bb2](https://github.com/briq-cloud/briqyard/commit/f75f0bb2c00a26cc06da425934f64da5fca87e3e))

- remove the stream of a backup that never finished (#138) ([f4939302](https://github.com/briq-cloud/briqyard/commit/f49393023a254e2d43594724ab609f0468f140e1))


### Maintenance

- make the pressure and backup-cut checks deterministic (#143) ([01f5c9f6](https://github.com/briq-cloud/briqyard/commit/01f5c9f65007d9a8b5aa587e451f682c02dd4bc1))

- call a copy without a sync unsynced (#144) ([77c5ae2d](https://github.com/briq-cloud/briqyard/commit/77c5ae2d7d7bf906893dee3f7bcfe1f38476bdf5))

## 0.1.21 — 2026-11-04

### Upgrade notes

- The init's digest changes once more with this release (ADR 0101): every seed sealed before it is refused until it is sealed again, in the order `docs/OPERATIONS.md` gives (Upgrade). From this release on, the digest changes only with the init's code, its dependencies, the toolchain, the target or the release profile. A seed also binds the image, the kernel, the VMM, the CPU template and the sizes: a release that changes none of these and leaves the digest alone keeps its seeds.
- A guest's `init_version` is now the guest protocol version, not the release.
- The `nested` class's kernel changes (`BRIDGE_NETFILTER` as a module): a host serving the class gets it by this upgrade.

### Fixes

- report a VMM killed over its memory ceiling (#132) ([64c53039](https://github.com/briq-cloud/briqyard/commit/64c53039459dd8fd2ce52706a2be2d87a3eb2c6b))

- br_netfilter is a module in the nested kernel ([4d22f944](https://github.com/briq-cloud/briqyard/commit/4d22f944d9f396b850923b85bdb01fd29efd8031))

- a fake zfs started after its parent exited ends too ([8d89b3af](https://github.com/briq-cloud/briqyard/commit/8d89b3affef07e34115c9ab4cd7f616afea4d698))

- a fork keeps the source's command unless the request sets one (#135) ([e48b6bb5](https://github.com/briq-cloud/briqyard/commit/e48b6bb5d4230af8ead572e382767f54784f2362))

- restrict workflow token permissions (#137) ([75c8e9e2](https://github.com/briq-cloud/briqyard/commit/75c8e9e2f04fda9502e69a39c15adea3d324298b))

- the init's digest changes only when the init does ([6dad7483](https://github.com/briq-cloud/briqyard/commit/6dad74831b4b243713bb7b01895dbe51eb0cd332))

- ADR 0101, what the digest depends on, gate rules, a workspace() test ([ffd7f042](https://github.com/briq-cloud/briqyard/commit/ffd7f042470c3c003fc01c401d225dd77d42716a))


### Maintenance

- chaos, isolation and OOM qualification (#129) ([4ba56103](https://github.com/briq-cloud/briqyard/commit/4ba5610326c9f66cc014a4b7188e9d8fb4ffb114))

## 0.1.20 — 2026-11-04

### Upgrade notes

Read these before rolling the release. The procedure is [Upgrade](https://github.com/briq-cloud/briqyard/blob/v0.1.20/docs/OPERATIONS.md#upgrade), and the notes of v0.1.19 still apply to a host coming from an earlier release.

- **Startup barrier on hosts with thousands of idle machine cgroups.** A host upgraded in place can hold thousands of empty machine cgroups left by machines that are gone. The barrier now accepts up to 65,536 of them, and so does the bound on recorded machines. The first start after the upgrade removes the idle ones, logging each orphan at `debug`. A v0.1.19 daemon on such a host stays `recovery_unresolved` and starts no machine until this release is installed.
- **Filesystem-consistent copies** (ADR 0092, the copy integration). A disk snapshot, backup or fork of a running machine now freezes the guest's filesystems around the disk copy by default, and syncs before a memory snapshot. The result says what it got: `consistency` is `filesystem`, `synced` or `crash` on snapshots, backups and forked machines. A busy source pays more than an idle one (about 450-600 ms added on a 4-vCPU bench, against about 42 ms idle; relative figures, not guarantees). Send `consistency: "crash"` on a request to skip the sync and freeze and accept a crash-consistent copy. A machine whose root disk was made before the guest init gained these operations reports `crash` with `init_too_old` until its root disk is made again.
- **The guest init digest may change with this release.** A host whose `templates.sandbox_recipes[*].init_sha256` (and `templates.init_ready_init_sha256`, if set) names the init must carry the new digest before the upgrade, as for v0.1.19: take it from the `briqyard-init-linux-x86_64` line of `SHA256SUMS-x86_64`. Otherwise the host stops advertising `sandbox-ready-v1` after the upgrade. When the digest changes, root disks, seeds and warm templates are made again and seeds sealed before are refused, not booted cold: follow the roll order in [Upgrade](https://github.com/briq-cloud/briqyard/blob/v0.1.20/docs/OPERATIONS.md#upgrade) and [Sandbox seeds](https://github.com/briq-cloud/briqyard/blob/v0.1.20/docs/SANDBOX-SEEDS.md).

### Features

- freeze a guest's filesystems around a disk copy (#127) ([f46e51f4](https://github.com/briq-cloud/briqyard/commit/f46e51f4a7b900bd16fb458b5b41ba476b5d7a08))


### Fixes

- a host with thousands of idle machine cgroups passes the startup barrier (#134) ([98f2c65c](https://github.com/briq-cloud/briqyard/commit/98f2c65c6382ef4c4bc17ece0dafcc8848678547))


### Maintenance

- judge daemon memory by its trend over cycles (#130) ([4a63d752](https://github.com/briq-cloud/briqyard/commit/4a63d752eea1d858c7b260b1c5806da47be56280))

## 0.1.19 — 2026-11-04

### Upgrade notes

Read these before rolling the release. The procedure is [Upgrade](https://github.com/briq-cloud/briqyard/blob/v0.1.19/docs/OPERATIONS.md#upgrade).

- **Every root disk, seed and warm template is made again.** The guest init changes (the CPU template, ADR 0087, and filesystem sync and freeze, ADR 0092), and its digest is part of the image key. Suspended machines, warm slots and seeds made before the upgrade are cold-only: no warm hit until the pools refill with the new identity.
- **A seed sealed before this release is refused, not booted cold.** A create naming an old-generation seed fails until the seed is sealed again (ADR 0087, ADR 0076). A control plane that names seeds rolls in three steps: stop naming them (its creates boot cold), upgrade the hosts and seal and qualify the seeds again, then name the new ones. Order and commands: [Upgrade](https://github.com/briq-cloud/briqyard/blob/v0.1.19/docs/OPERATIONS.md#upgrade) and [Sandbox seeds](https://github.com/briq-cloud/briqyard/blob/v0.1.19/docs/SANDBOX-SEEDS.md).
- **Guests have no virtualization extensions** (ADR 0087). A guest that used VMX or SVM loses it at its next cold boot. A machine that needs `/dev/kvm` asks for the `nested` runtime class.
- **Runtime classes are off by default** (ADR 0088). A host serves only the `default` class until it is upgraded with `--runtime-class nested`, which also needs KVM's `nested` parameter on (a reboot when it was off). A nested machine resumes nothing: every start is a cold boot. Existing configurations are unchanged. The release workflow builds the class's kernel and ZFS modules for x86_64 and attaches them with their source links.
- **Memory prerequisites and the unit change** (ADR 0084, ADR 0065). A VMM's memory is contained in its own cgroup and the host reserves the VMM's physical ceiling for every machine, assigned runs included. The installer (the upgrade path) rewrites `briqyardd.service` and `briqyard-fleet.service` with `OOMScoreAdjust=-900` and `OOMPolicy=continue`, turns swap off, stops and masks KSM and `systemd-oomd`, and sets the ZFS ARC ceiling. It refuses to continue while swap or KSM holds pages: drain the host first. A binary replaced by hand without the installer leaves the host with `memory_protection` true: it serves its machines and takes nothing new.
- **`physical capacity` refusal.** `memory_mb` plus `capacity.reserved_memory_mb` plus the ZFS cache ceiling must fit in physical memory; otherwise the host takes nothing new (`memory_protection`: `capacity_exceeds_physical_memory`, with the figures in the daemon log). Lower `memory_mb` or the reservation, or leave `memory_mb` unset.
- **Quiet boot.** The guest kernel console shows errors, panics and the OOM kill line only. Add `loglevel=7` to the kernel arguments to restore the rest on a host being debugged (ADR 0093). Readiness is noticed within 5 ms instead of 100 ms. Saved snapshots resume with the command line they were taken with.
- **Volume-free seeds** (ADR 0091). A recipe may declare `volume_gb: 0`; one image and size can be approved with and without a volume. The builder request now names its volume (`volume: {size_gb, mount: "/work"}`), and omitting it builds the volume-free shape: a request that relied on the recipe's volume is refused until it names one. Run journals of volume-free machines cannot be loaded by a previous-release daemon.
- **Filesystem-consistent copies, first part** (ADR 0092). The guest init gains freeze, thaw and sync operations, and a seed is sealed after a sync. Snapshots, backups and forks do not use them yet and still take crash-consistent copies.
- **Rollback.** Use the installer's retained set (`/etc/briqyard/rollback.<suffix>`) with a compatible release, as described in [Upgrade](https://github.com/briq-cloud/briqyard/blob/v0.1.19/docs/OPERATIONS.md#upgrade).

### Documentation

- 0088 runtime classes, and a nested class with /dev/kvm ([fdcc6751](https://github.com/briq-cloud/briqyard/commit/fdcc67514e729d2c8807080c09903906283303c0))

- 0088 matches the kernel build and the code (kernel options, drive slot, bad_state) ([2cbeb952](https://github.com/briq-cloud/briqyard/commit/2cbeb952994ef5cb0199dbc1deedbab6a4db3f4a))

- runtime classes (ARCHITECTURE, OPERATIONS, KUBERNETES-MAP, ADR index, counts) ([7321bb05](https://github.com/briq-cloud/briqyard/commit/7321bb05c110964083f3288f8006f779085b3be2))

- the index in order ([f8518e06](https://github.com/briq-cloud/briqyard/commit/f8518e063ab496593e2d4e361838b49bcbe650f3))

- enabling a class with KVM's nested off, the reboot's steps ([425c7e6b](https://github.com/briq-cloud/briqyard/commit/425c7e6bfc58ddde6429fdb109d604ce5f999ec6))


### Features

- build the nested class's guest kernel and ZFS modules ([7cca2cdb](https://github.com/briq-cloud/briqyard/commit/7cca2cdbf0b9a49486b14f0a5617da28ab4bda1a))

- no virtualization extensions in guests ([53f174ef](https://github.com/briq-cloud/briqyard/commit/53f174ef00ffe6fd23653645bb0dc9c42f468735))

- reconcile PR101 changes with v0.1.18 (#108) ([6eb7c20e](https://github.com/briq-cloud/briqyard/commit/6eb7c20ef8b34ef5f288ee1a3aa795dade5e6718))

- sandbox seeds without a data volume (#116) ([90cbcba5](https://github.com/briq-cloud/briqyard/commit/90cbcba580d43fd0a4b15cd960a80390f431abd4))

- report backup failures and capacity refusals (#103) ([853d1144](https://github.com/briq-cloud/briqyard/commit/853d1144164b0bda2e139f8634d70510599fee76))

- add bounded read-only object census (#109) ([6847144a](https://github.com/briq-cloud/briqyard/commit/6847144a0e6a02672e33c1cde96de9878a9eb390))

- runtime_class on machines, runtime_classes on hosts ([2933cab0](https://github.com/briq-cloud/briqyard/commit/2933cab07d3a0fbe89a402e0a891fb6ccb7bc02c))

- runtime classes, and a nested class booted without the CPU template ([aacc4a7b](https://github.com/briq-cloud/briqyard/commit/aacc4a7b63bd198342dc1cf319a76d1c0329e78d))

- place by runtime class ([05333171](https://github.com/briq-cloud/briqyard/commit/053331718c5aa1ac8731692004292d00c72fb847))

- CLASS in machine ls, --runtime-class, classes in host ls; doctor allows nested on a nested host ([2a669b87](https://github.com/briq-cloud/briqyard/commit/2a669b8723225d63a297a62540b3dd2aaebefe63))

- BRIQYARD_RUNTIME_CLASSES=nested in the bootstrap, a runtime classes section in the e2e suite ([1ee18bdd](https://github.com/briq-cloud/briqyard/commit/1ee18bdd44f6c8c14969961dfd815df47e87d1c4))

- expose cached registry backup observations (#105) ([440be328](https://github.com/briq-cloud/briqyard/commit/440be328eef1a4267f82eafc863c0df4bc3a0905))

- sync and freeze a guest's filesystems, sync before a seal (#122) ([5e4d04a0](https://github.com/briq-cloud/briqyard/commit/5e4d04a0a21e842203d0d5251ca8a1e8bf477aa8))

- first-enable a runtime class through a host upgrade ([341173da](https://github.com/briq-cloud/briqyard/commit/341173dae8e7eca7fffd24d16771b2d54a1ebf39))

- contain VMM memory and reserve physical capacity (#102) ([fca50022](https://github.com/briq-cloud/briqyard/commit/fca50022bf3888887827f078035610f277197987))


### Fixes

- zero the change times in the modules image ([077c0c28](https://github.com/briq-cloud/briqyard/commit/077c0c289508f998857973486ed6df90e89a8ee3))

- fail the workflow when the build or the smoke fails ([c31083fc](https://github.com/briq-cloud/briqyard/commit/c31083fc9ac90f944bd1ee0c77ed4d9205e6277c))

- give mke2fs a non-zero fake time ([dd537d09](https://github.com/briq-cloud/briqyard/commit/dd537d09aed7730e92a225b711650ea48792019c))

- the smoke gates the release, source links in the notes ([4c12969c](https://github.com/briq-cloud/briqyard/commit/4c12969cb65474066b8e6aaca24daab7f75fc47d))

- CPUID read builds on every toolchain; e2e negates inside the guest ([72eabe09](https://github.com/briq-cloud/briqyard/commit/72eabe09a204a3e93146bf5c19796c4ebaaf52fe))

- let a non-root app open its console (#115) ([d943ee1d](https://github.com/briq-cloud/briqyard/commit/d943ee1d1ab7a93892b0497de9b72910c06dfb68))

- retry a vsock handshake that is reset, answer 409 when it stays reset (#117) ([81fe6490](https://github.com/briq-cloud/briqyard/commit/81fe649092f56b572da70da58fc414ca43fea8d7))

- retain registry publication ownership (#104) ([68fe1d48](https://github.com/briq-cloud/briqyard/commit/68fe1d48c4f1947c03aaca8b6dfc61ae739ac0cc))

- review of the runtime classes (upgrade keeps nested, modules on resume, restore by class) ([291b6c9e](https://github.com/briq-cloud/briqyard/commit/291b6c9e9cb844fb3304f7f1a0ed612b71d554af))


### Maintenance

- drop the change-time rewrite of the modules image ([8fd9fdad](https://github.com/briq-cloud/briqyard/commit/8fd9fdada05c0c868780482badb925668fabb08c))

- run the native suites on hosted KVM runners (#112) ([fd9ec193](https://github.com/briq-cloud/briqyard/commit/fd9ec193c6b512a214c99cc1a07555c08870fdf8))

- run the two-host suites on hosted KVM runners (#119) ([3139cae4](https://github.com/briq-cloud/briqyard/commit/3139cae4a682e6cc63be766ff6c73d1c2d9432f3))

- print the machines' consoles when a churn cycle fails (#121) ([c92b6dab](https://github.com/briq-cloud/briqyard/commit/c92b6dab02a7b61ea0a11493604e3ba0dbe443e6))

- the runtime class is part of the placement policy ([ca66f043](https://github.com/briq-cloud/briqyard/commit/ca66f04358fb14dfb0b49f6a4c13976c52f5a8dd))

- runtime class fixes (default class in the table, no class for a fork naming default, bootstrap installer tests) ([cd7d5ae7](https://github.com/briq-cloud/briqyard/commit/cd7d5ae70ad53889c3d43101ffd68370013fd578))

- config_drive takes the class's modules mount ([4bbfe8a2](https://github.com/briq-cloud/briqyard/commit/4bbfe8a2d7dc862677195c66c642b50c594a68c1))

- wait for the second host's own daemon before probing it (#124) ([9b947f82](https://github.com/briq-cloud/briqyard/commit/9b947f82f87461f4ec3002fbea4653111a8deb27))


### Performance

- notice guest readiness without polling delay and keep kernel messages off the serial console (#123) ([4825d4e7](https://github.com/briq-cloud/briqyard/commit/4825d4e7ba719507cb278a321b8987f87f67dd9a))

## 0.1.18 — 2026-11-03

### Documentation

- link contributor release and upgrade procedures ([8d5ef8e6](https://github.com/briq-cloud/briqyard/commit/8d5ef8e6504bb3586c0c4d83537e632a92217a66))

- clarify release and upgrade instructions ([8e7a4b1b](https://github.com/briq-cloud/briqyard/commit/8e7a4b1b0ba820fbd4bddf5e913e10e599c080d2))


### Features

- route sandbox creates through ready unbound slots (#106) ([14446432](https://github.com/briq-cloud/briqyard/commit/14446432eeac33db01c19dcced6a5b4d239ab586))


### Maintenance

- automate changelog preparation ([c409fa19](https://github.com/briq-cloud/briqyard/commit/c409fa19d97ad3e6d45f3e5dd38b771b56a33237))

## 0.1.17 — 2026-11-02

- Add acknowledged, cancellable exec streams across the daemon and guest init.
- Return a stable `unsupported` terminal code when the running guest lacks exec-stream capability.
- Require observed host telemetry before deriving zero-valued period usage.
- Bound stress runs and verify resource ownership.
