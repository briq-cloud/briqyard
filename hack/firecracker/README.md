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
Successful jobs retain debug library test executables for one day, with exact
source/tree, lockfile, toolchain, architecture and binary hashes for isolated
KVM validation. Obtain them only from a verified successful CI run on the expected
PR commit; a self-declared manifest alone is not trusted binary provenance.
These are debug library test builds; upstream uses an empty seccomp policy for
this build mode. They are not release or deployment artifacts.

This validation does not change deployed Firecracker pins, publish a release binary, or
enable checkpoint capture. Exact deployed-binary provenance, isolated storage
fault and power-loss checks, and complete checkpoint commit/recovery gates remain
required before activation. Initial capture eligibility remains Sync-only.

Run `python3 hack/firecracker/prepare.py CHECKOUT` on a clean checkout at the pinned
base, then use `validate.py CHECKOUT OUTPUT_DIRECTORY` with the pinned toolchain.
The output directory must be outside the source checkout and initially absent.

The same workflow also produces `checked-firecracker-cli-<architecture>` candidates
for x86_64 and aarch64. After the portable validation succeeds, `build_cli.py`
reuses its prepared source and Cargo target to build release Firecracker and
jailer for the native musl target. The helper stages only Linux UAPI headers
for the musl C compilation, records their hashes and package versions, and
rejects empty seccomp-policy warnings or a dynamic ELF loader/dependency.
Cargo's production build-script event identifies the compiled seccomp bytecode;
the artifact records its hash alongside the pinned source policy, exact patched
tree, workflow commit/run, lockfile, toolchain and binary hashes. The artifact
also contains versions, ELF evidence, build logs and upstream license notices.

These static CLI candidates are retained for seven days. Verify the successful
workflow run and expected source commit before using its artifacts; the manifest
alone does not establish provenance. This workflow neither publishes a normal
release nor changes bootstrap/installed binaries. Runtime acceptance and exact
per-architecture artifact pins are still required before release integration.
