# 0072: Identity before memory-clone activation

Date: 2026-10-31
Status: accepted; guest protocol implemented, host publication unavailable

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

This protocol does not authorize template publication. Host enforcement must add a
reviewed digest-pinned public recipe and matching init, quarantine from birth,
immutable shared artifacts, durable read references, deletion fencing, strict
memory restore without cold fallback, and full capacity admission. Capability must
remain unavailable until these paths and native effective-MAC, VMGenID and VMClock
behavior are qualified against the pinned VMM/kernel. SSH recipes require explicit
fresh key generation before a listener can be activated.

`init-ready-v1` holds before the first workload exec. It does not support cloning
an already-running service. A service profile requires qualified application park
and post-clone hooks that preserve prepared state while resetting application RNG,
sockets and cached identity; unsupported profiles are refused. Paused warm slots
must use the same identity and artifact contracts before atomic claim and activation.
