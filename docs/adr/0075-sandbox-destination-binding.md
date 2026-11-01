# 0075: Bind sandbox configuration before main

Date: 2026-11-01
Status: guest protocol candidate; host integration and native qualification pending

A pristine memory restore must install destination application configuration before
main or exec can read it. The identity-only `init-ready-v1` contract and existing
paused warm claims remain unchanged.

The new internal `sandbox-ready-v1` profile requires an empty seed configuration:
no command, environment, boot files, volumes, user, hostname or network settings.
The guest enters the existing identity quarantine and accepts only ping,
`destination_bind_v1` and generation-bound activation. No daemon recipe selects
this profile yet; ordinary create and pool selection are unchanged.

A bind contains fresh identity, a complete resolved guest configuration, boot file
bytes and a host receipt digest. The host digest must bind ownership and its full
machine specification, including probes, metadata, egress policy, image generation
and exact size. The guest does not authorize these host-owned values. The
configuration's hostname and network must match its identity message. This version
accepts exactly one ext4 disk at `/dev/vdc` mounted at `/work`; the host must attach
a newly allocated destination volume before binding. Other mount shapes are
rejected. Files are supplied once, without duplicate or traversal paths; identity
and runtime paths are reserved. File installation reuses descriptor-relative
upload helpers and never follows image symlinks.

Before side effects, init creates an exclusive root-disk consumed receipt and
fsyncs both it and the root directory. Its SHA-256 covers the protocol domain and
the complete serialized bind, including identity, resolved config, files and host
receipt. Identity reset reuses the existing entropy, clock and network helpers.
Mount seeding precedes boot-file installation. Main and subsequent exec read the
installed config/environment, never the seed values. Filesystems are flushed
before the acknowledgment returns its fingerprint and effective identity.

Successful live replay returns the same identity and fingerprint without side
effects. A changed request conflicts. Any partial installation fails closed; init
cannot retry it or activate. A process restart with the consumed disk refuses the
sandbox boot entirely: the durable receipt is a consumption fence, not a reboot
recovery journal. An interrupted bind therefore retains its machine/reservation
for host reconciliation; it does not authorize another slot or cold fallback.
The host must durably save the acknowledgment before activation and keep TAP
quarantine until that point. Activation requires fresh supported wall time; main
must start before exec/file work becomes available.

This guest-only candidate does not provide ordinary-create selection, reviewed
sandbox-image provenance, exact-size admission, ownership authorization, fresh
volume allocation, gateway policy, probe persistence or host ACK/quarantine
integration. Those checks must exist before enabling the profile. Runtime-native
restored-guest behavior and crash recovery remain unqualified; cross-target
compilation alone does not establish them.
