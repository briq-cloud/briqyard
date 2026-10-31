# Named memory templates

The current candidate supports `init-ready-v1`: a booted kernel and init parked
before the workload's first exec. It does not clone an already-running service or
application-prepared process. Service-ready recipes and paused warm pools remain
unavailable. No startup or memory-sharing performance result is qualified yet.

The reviewed public recipe is recorded in
[recipes/alpine-init-ready-v1.json](recipes/alpine-init-ready-v1.json), including
platform OCI/config/layer digests and exact public Dockerfile source. It fixes one
vCPU, 256 MB and `/bin/sleep 2147483647` after activation. The image's default shell
never executes. The recipe trusts the official public build inputs; checking known
identity files does not prove arbitrary image bytes secret-free.

An operator binds `templates.init_ready_init_sha256` to the SHA-256 of the exact
locally built `briqyard-init`. Empty is disabled. A jailer and default kernel
arguments are required. Image-cache keys include the init digest. The guest reports
the digest of its actual running executable, and mismatches refuse the builder or
clone. Guest MAC, entropy reset, VMGenID and VMClock behavior still require native
qualification against the pinned runtime. Fleet capability remains false pending
that qualification.

On a candidate host configured with that binding, the x86_64 recipe is:

```sh
briqyard machine run --namespace example --name template --memory 256 --sleep never \
  --template-build init-ready-v1 \
  --image docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f
briqyard machine snapshot create TEMPLATE_ID --memory --template --name ready
briqyard machine fork TEMPLATE_ID --snapshot ready --name clone
```

For aarch64, use the platform digest in the recipe manifest. A builder reports its
profile and remains `ready=false`; reaching `running` means init reached the
pre-main barrier. It permits status, controlled memory seal and destroy. Workload,
network, file, volume, probe, restart and credential overrides are refused. It
starts with an unbridged, down host TAP and an unaddressed guest interface.

The fork response accepts creation; wait for the clone's readiness before using it.
Readiness follows identity acknowledgment, durable host recording, network
activation, one main start and a successful first command. API `memory_origin`
reports the immutable snapshot, source host, restore stage and acknowledged
identity. The inherited RAM marker must match the sealed artifact. Filesystem
writes use an independent root clone. Per-exec environment is ordinary exec
behavior; it does not change the already-running main process.

Memory restore uses the same immutable File inode through retained read-only jail
links. Missing or incompatible backing fails creation; it never falls back cold.
Every clone reserves its full configured capacity. Snapshot/source deletion,
restore and root replacement conflict while a durable reader exists. Destroying a
clone releases the reader only after confirmed VMM exit and local backing cleanup.

Incomplete clones after daemon restart remain quarantined with their backing and
reservations retained; destroy them explicitly. Ambiguous exit or corrupt reader
metadata blocks cleanup. Running completed clones use the existing incarnation
adoption path. Templates and clone records cannot move to another namespace/host.
