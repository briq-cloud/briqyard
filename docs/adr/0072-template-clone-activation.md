# 0072: Identity before memory-clone activation

Date: 2026-10-31
Status: accepted; restricted init-ready implementation candidate, native qualification pending

A restored memory image includes kernel and process identity. A distinct TAP or a
successful ping does not establish that a clone can safely execute work or send
traffic. Memory cloning must therefore cross an explicit identity barrier before
activation.

An init born with the internal `init-ready-v1` profile keeps eth0 down and
unaddressed, removes machine identity, SSH host keys and saved random seeds, and
serves only status and clone-control messages. It does not execute the image's
command or accept exec/file operations. Ordinary boots retain their existing
behavior. Unknown profiles and addressed template boot configurations fail closed.

`clone_configure_v1` accepts one host-generated generation, hostname, network
identity, fresh trusted host entropy and wall clock. Init removes inherited routes,
neighbors and addresses, sets a locally administered unicast effective MAC, credits
entropy and forces a kernel CRNG reseed, creates machine identity with getrandom,
and replaces hostname, hosts and resolver files. Success acknowledges the effective
identity while the workload remains blocked. Partial configuration is terminal.
Replaying the same message returns the original acknowledgment; a differing
configuration cannot reset an identity that might already be in use.

The host must durably record the acknowledgment before sending
`clone_activate_v1` for that generation. Activation starts the fixed image command
once. Status distinguishes identity completion, activation request and an actually
started main process; ping alone is insufficient for readiness.

Publication is limited to a
reviewed digest-pinned public Alpine recipe and matching actual init executable. Host
enforcement includes quarantine from birth, immutable shared artifacts, durable read
references, deletion fencing, strict memory restore without cold fallback, and full
capacity admission. Default-off availability is derived from the enabled enforced profile, exact init
binding, jailer and compatibility support. It reports `init-ready-v1` explicitly.
Native effective-MAC, VMGenID and VMClock behavior must still be qualified against
the pinned VMM/kernel before release. SSH recipes require explicit
fresh key generation before a listener can be activated.

`init-ready-v1` holds before the first workload exec. It does not support cloning
an already-running service. A service profile requires qualified application park
and post-clone hooks that preserve prepared state while resetting application RNG,
sockets and cached identity; unsupported profiles are refused. Paused warm slots
must use the same identity and artifact contracts before atomic claim and activation.

## Amended 2026-11-06: the disk clone runs outside the seed's lock

A named clone's `zfs clone` of the seed's snapshot no longer runs under the seed's `Entry.lock`. The lock was held across it, so every create from one seed waited for the previous clone (one seed: a strict 74 ms cycle, about 14 creates/s on a 24-core host, while clones of different sources ran in parallel to about 240/s).

The durable reader of the destination is what holds the snapshot. `reserve_named_clone` writes it under the seed's lock before the create is answered; `destroy`, `restore_snapshot`, `delete_snapshot`, `remake_root` and `tidy` refuse while one exists, each checking it under that lock, and nothing else removes, rolls back or renames the snapshot. `make_disks` takes the lock to validate the source, checks that the destination's reader names this source, snapshot and generation (refusing otherwise), and releases the lock before the clone. The reader's lifetime is unchanged: it goes with the clone's machine. Disk forks and restores keep the lock across their clone. Lock order is unchanged (the new machine's lock, then the source's); the sandbox create path still holds its daemon-wide locks while it waits for the seed's lock to reserve, which is a separate change.
