# ADR 0088: Runtime classes, and a nested class with `/dev/kvm`

Date: 2026-11-03 · Status: accepted; amends ADR 0087 (a host serving `nested` keeps KVM's
`nested` on)

## Context

A machine that runs a hypervisor of its own (a sandbox that develops and tests briqyard, an
emulator, a VM-based CI job) needs `/dev/kvm` in its guest. Kubernetes answers "this pod needs
another runtime" with a RuntimeClass: a named handler the node declares, its scheduling; the pod
names it. briqyard has one runtime (`../KUBERNETES-MAP.md`: RuntimeClass ★), and ADR 0087 takes
VMX and SVM out of every guest.

Facts, read in Firecracker v1.17.0 (`95f868c8e`) and Linux 7.4-rc1 on 2026-11-03:

| | Fact | Source |
|---|---|---|
| 1 | Firecracker saves no nested state: no `KVM_GET_NESTED_STATE`; `MSR_VM_HSAVE_PA`, `VM_CR` and the VMX MSRs are not in its MSR list. A snapshot taken while a nested guest runs cannot resume it | FC `arch/x86_64/vcpu.rs` (`VcpuState`), `arch/x86_64/msr.rs`; Linux `Documentation/virt/kvm/api.rst` (`KVM_GET_NESTED_STATE`) |
| 2 | Firecracker does not test nested virtualization; the guests a nested guest runs are isolated from each other only by that guest's own hypervisor | FC `arch/x86_64/msr.rs`, firecracker-microvm/firecracker#1721 |
| 3 | The pinned guest kernel has no KVM, no nftables `inet`/`bridge` families, no `masquerade`, `reject`, `limit`, `fib`, no ctnetlink: briqyard cannot run on it | its embedded config (`vmlinux-6.18.54`) |
| 4 | aarch64: Firecracker never sets `KVM_ARM_VCPU_HAS_EL2`; nested is x86_64 only | FC `arch/aarch64/vcpu.rs` |
| 5 | A bug in KVM's nested emulation is a host compromise (CVE-2021-29657, CVE-2021-3653, CVE-2023-30456) | NVD |

## Decisions

**A host declares runtime classes in its configuration; a machine names one.**

```yaml
runtime_classes:
  nested:
    kernel: /var/lib/briqyard/classes/nested/vmlinux
    modules: /var/lib/briqyard/classes/nested/modules.ext4   # optional, needs release
    release: 6.18.54-briqyard-nested
    versions: /var/lib/briqyard/classes/nested/versions.json # optional, for the host's status
    nested: true
```

`default` is the host's `kernel`, no modules, `nested: false`: always there, never written.
`CreateMachineRequest.runtime_class` (absent: `default`) is kept on the machine, shown in its
status and in `machine ls` (`CLASS`), and fixed for its life: a resize keeps it; a fork, a
restore and a backup's manifest carry their source's. A host without the class answers 400
`invalid` (`runtime class nested is not served by this host`). The daemon refuses to start with
a class whose kernel or modules file is missing, or with `nested: true` on aarch64 or while
KVM's `nested` parameter is off.

**A `nested: true` class boots without ADR 0087's template.** Its machines see VMX or SVM; every
other machine on the host keeps the template, so the host's KVM loads with `nested` on only
where the operator chose to serve the class: `hack/bootstrap-host.sh` writes `nested=0`
(ADR 0087) unless `BRIQYARD_RUNTIME_CLASSES` names `nested`, and `briqyard doctor` does not warn
about `nested` on a host configured with a `nested: true` class. The class's identity
(`cpu_config: none`, its kernel's SHA-256) is its own.

**A class's modules reach the guest as a read-only drive.** `modules` is an ext4 image of one
`lib/modules/<release>` tree with its `depmod` files, built with the class's kernel. The daemon
attaches it read-only as the last drive, after the volume if the machine has one (Firecracker
names virtio disks in the order it is given them: `/dev/vdd` with a volume, `/dev/vdc` without),
and lists it in the guest's configuration (`mounts`, with `read_only`, which ADR 0087 added); the
init mounts it at `/lib/modules/<release>` before the program starts. The class configuration
carries `release`, which names that directory, and optionally `versions`, the `versions.json` of
the release, which the host's status reads. An image never carries modules, so it never has to match a host's kernel. The one
coupling left: an image's ZFS tools must be of the OpenZFS version of the class's `zfs.ko`; the
host's status shows each class's kernel release and OpenZFS version.

**A nested machine takes no memory snapshot** (fact 1). A stop with `suspend` (asked, idle, a
daemon's shutdown) is a plain stop, its event saying `suspend: refused (runtime class nested)`;
a wake is a cold boot; a hand-over (ADR 0051) adopts it as any machine; a snapshot with memory
and a memory fork are 409 `bad_state` naming the class; no warm slot or seed is made of it.
Its disks fork, back up and restore as any machine's.

**The fleet places by class.** A heartbeat lists the classes the host serves
(`runtime_classes`, as `warm_pool_profiles`). A create, fork or restore naming a class places a
new namespace only on a host serving it; a namespace already pinned to a host without it is
refused 400 `invalid` (`namespace n1 is on host h1, which does not serve runtime class nested`),
as a region is (ADR 0025). A `default` namespace goes to a host that does not serve `nested`
when one has room (fact 5: a host that serves it shares the risk with every machine on it). The
dedicated host is the intended deployment; no taint primitive, this one rule.

**The `nested` class's kernel is built here.** Firecracker's 6.18 guest configuration (the one
upstream validates) plus `hack/kernel/nested.config`: `VIRTUALIZATION`, `KVM`, `KVM_AMD`,
`KVM_INTEL`, `NF_TABLES_INET`, `NF_TABLES_BRIDGE`, `NF_TABLES_ARP`, `NFT_BRIDGE_META`, `NFT_MASQ`,
`NFT_REJECT`, `NFT_REJECT_INET`, `NFT_BRIDGE_REJECT`, `NFT_LIMIT`, `NF_TABLES_IPV6`,
`NFT_FIB_IPV4`, `NFT_FIB_IPV6`, `NFT_FIB_INET`, `NF_CT_NETLINK`, `MODULE_UNLOAD`, built in, and
`LOCALVERSION=-briqyard-nested`: the release is `6.18.54-briqyard-nested`. OpenZFS is built against
it as a loadable module, never into the kernel: CDDL and GPL code combined in one binary is not
distributable, a separate module is how distributions ship it. The release workflow builds both
for x86_64 and pins their SHA-256 in `SHA256SUMS-x86_64`: `nested-vmlinux-x86_64`,
`nested-modules-x86_64.ext4` and `nested-versions-x86_64.json` (`kernel_release`, `kernel`,
`openzfs`, the sources and their SHA-256). The bootstrap installs them when
`BRIQYARD_RUNTIME_CLASSES` names `nested`.

**Acceptance.** On an x86_64 host serving `nested`: a `nested` machine lists `/dev/kvm`, and inside
it `cargo test --workspace` (the root test included), `hack/e2e.sh` and `hack/fleet-smoke.sh`
against daemons started there. aarch64 cannot run it (fact 4): the Mac dev loop does not cover it.

Rejected: a boolean machine field (no kernel or modules to carry, no host to declare it); a second
VMM that saves nested state (a second jail, seccomp, snapshot and vsock path, two VMMs to patch);
modules in the image (an image bound to a host's kernel); a distribution kernel with its own
signed `zfs.ko` (vsock is a module there, needed before the init can talk; untested under
Firecracker).

## Consequences

- KVM's nested emulation is reachable only from `nested` machines, on hosts that serve the class.
- A nested machine resumes nothing: every start is a cold boot.
- A second kernel and a ZFS module to rebuild on a security fix, from pinned sources.
- Not built: classes with another VMM, per-class overhead, tolerations.
