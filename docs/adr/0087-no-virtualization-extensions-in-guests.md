# ADR 0087: No virtualization extensions in guests

Date: 2026-11-03 · Status: accepted

## Context

A guest needs VMX (Intel) or SVM (AMD) in its CPUID only to run a hypervisor of its own. Facts,
read in Firecracker v1.17.0 (`95f868c8e`) and Linux 7.4-rc1 on 2026-11-03:

| | Fact | Source |
|---|---|---|
| 1 | `kvm_amd` and `kvm_intel` load with `nested` on by default; KVM then lists SVM (VMX) in its supported CPUID and fills leaf `0x8000000A` | `svm/svm.c` (`nested = true`, `kvm_cpu_cap_set(X86_FEATURE_SVM)`), `vmx/vmx.c`, `cpuid.c` |
| 2 | Firecracker builds a guest's CPUID from KVM's supported CPUID, then a template, then its normalization, which leaves VMX and SVM as they are; only its static templates clear them. briqyard sets no template (ADR 0028) | FC `arch/x86_64/mod.rs`, `cpu_config/x86_64/cpuid/normalize.rs`, `amd/normalize.rs`, `static_cpu_templates/t2a.rs` |
| 3 | KVM lets a guest into its nested emulation only when the guest's CPUID has the bit: `EFER.SVME` is refused without SVM (`__kvm_valid_efer`), the VMX MSRs and `CR4.VMXE` without VMX | `svm/svm.c`, `vmx/vmx.c`, `x86.c` |
| 4 | A snapshot restores the CPUID it was taken with | FC `arch/x86_64/vcpu.rs` (`restore_state`) |

So a host with KVM's default gives every guest the extensions, and KVM's nested emulation (the
VMCB/VMCS checks and their history of bugs) is reachable from any guest whose root loads a
module. No machine briqyard runs needs it.

## Decisions

**Every x86_64 machine boots with VMX and SVM cleared from its CPUID.** Before the boot, the
daemon sends Firecracker a custom CPU template (`PUT /cpu-config`) of CPUID modifiers only: leaf
`0x1` ECX bit 5 (VMX) to 0, leaf `0x80000001` ECX bit 2 (SVM) to 0, leaf `0x8000000A` EAX–EDX to 0.
No MSR, no other bit. Fact 3 makes it the gate. aarch64 sends nothing: Firecracker gives its
guests no EL2.

**The template's generation is part of the boot identity.** `BootIdentity` gains `cpu_config`, the
SHA-256 of the template as sent (`none` on aarch64), and its schema becomes 2. Every check of
the boot identity's schema reads the daemon's current one: compatibility, sealing a seed or a
slot, and the advertisement of named-memory profiles, so a host keeps advertising its profiles
and its pools refill with the new identity. (The versions of the template-birth and clone-artifact
records are their own and stay.) A run's recorded identity of an older schema stays readable
(`known`), so recovery of an assigned run still matches. A memory snapshot, a paused warm slot or
a seed of another generation, or of schema 1 (a missing field is the generation before this
one), never qualifies for a memory load. A suspended machine's next start is a cold boot (ADR
0005 allows it); so is one whose record has no identity at all. A create naming a seed of another
generation is refused, as for any seed that does not match the host (`memory template boot
identity is incompatible`); falling back to a cold create of the same image and size needs an
origin the answer can report and a receipt for the retry, and is left to its own change. Fact 4
is why: a snapshot of an unmasked guest would resume unmasked. Records written before stay
readable.

**A guest mount may be read-only** (`Mount.read_only`, absent: false), for ADR 0088's modules
drive. It ships here so that the init, whose SHA-256 keys the seeds, changes once: one seed
re-qualification for both.

**Hosts load KVM with `nested` off.** `hack/bootstrap-host.sh` writes
`/etc/modprobe.d/briqyard-kvm.conf` (`options kvm_amd nested=0`, `options kvm_intel nested=0`):
with it, the extensions never enter KVM's supported CPUID, and the template is a second gate.
The parameter is read-only while the module is loaded, so it applies from the host's next boot.
The daemon logs `kvm_nested` at start, and `briqyard doctor` warns while it is on.

## Consequences

- A guest that used VMX or SVM loses it at its next cold boot.
- After the upgrade, every suspended machine, warm slot and seed made before it is cold-only: no
  warm hits until the pools refill with the new identity, and a seed generation has to be
  qualified and approved again (ADR 0076).
- A machine that needs the extensions gets them through a runtime class that asks for them
  (a later ADR), never by default.
