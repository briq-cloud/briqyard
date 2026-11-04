# Changelog

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
