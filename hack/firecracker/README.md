# Checked snapshot preparation validation

This directory carries a local patch series against the exact Firecracker commit in
`pin.json`. Apply the entire series before building. Both patches retain the
upstream Apache-2.0 copyright and license notices. The upstream source and license
are available at https://github.com/firecracker-microvm/firecracker.

The patches propagate activated block-device preparation failures through snapshot
creation before opening state or memory outputs. MMIO and PCI preparation finish
before transport serialization. Inactive devices perform no preparation IO;
unhandled block implementations refuse checked preparation. Snapshot formats and
ordinary event handling remain unchanged.

The dedicated workflow builds library tests on native Linux amd64 and arm64,
runs exact named regressions, and checks that discarding the checked flush result
makes a Sync regression fail. Positive and negative builds use separate targets.
Kernel-dependent tests run only when the corresponding KVM and io_uring probes
succeed. Their absence is recorded as **unverified**, never as a passed test.
A successful portable job alone does not satisfy the runtime activation gate.
These are debug library test builds; upstream uses an empty seccomp policy for
this build mode. They are not release or deployment artifacts.

This validation does not change deployed Firecracker pins, publish a binary, or
enable checkpoint capture. Exact deployed-binary provenance, isolated storage
fault and power-loss checks, and complete checkpoint commit/recovery gates remain
required before activation. Initial capture eligibility remains Sync-only.

Run `python3 hack/firecracker/prepare.py CHECKOUT` on a clean checkout at the pinned
base, then use `validate.py CHECKOUT OUTPUT_DIRECTORY` with the pinned toolchain.
The output directory must be outside the source checkout and initially absent.
