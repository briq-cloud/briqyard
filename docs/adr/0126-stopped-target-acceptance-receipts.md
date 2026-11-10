# 0126: Stopped target acceptance receipts

A stopped state alone cannot authorize changing a machine's backing configuration.
An uncertain HTTP response also cannot prove whether a target was persisted.

`POST /v1/machines/:id/stopped-update` accepts only an ordinary image-created machine.
It requires `If-Match`, a claim nonce, an image and a complete environment. Under the
machine transition lock it checks PID zero, any retained live handle's exit and the
native launch settlement. Settlement includes the verified startup recovery domain;
legacy stopped records need no invented process or boot receipt. Unknown authority
fails closed. Assigned, template and source-created machines keep their own lifecycle.

One crash-durable machine record contains the pending next-start target, cleared
current suspend eligibility and the receipt. Optional `probes` replaces the probes in
that same durable record; omitted preserves them and `{}` clears them. Probe validation
precedes all effects. Omitted probes retain the existing request commitment bytes. There is no pull or boot. The data disk and backups stay unchanged. A no-op target still requires settlement and advances the version.
Historical snapshots remain available. Ordinary PATCH semantics remain unchanged.

Accepted nonces remain reserved. A canonical request commitment includes the machine,
CAS version and full request. It remains inside the daemon's privileged record and
is redacted from Debug output. The public receipt exposes only identity and version.

An uncertain response is recovered by exact nonce GET, without replaying POST. The
existing record-write gate orders acceptance with every ordinary writer. After rename,
memory retains the complete candidate even if directory sync fails. A durability latch
requires directory sync before later writes or lifecycle effects. Loaded receipts start
latched too. Known pre-rename failures leave the old record intact.

Acceptance reserves its event version under the event log lock before writing the
record. Only a successful durable write emits the acceptance event. A failed write
burns that version without announcing acceptance; exact-nonce recovery stays status-only.
The write callback holds existing machine locks and acquires no further machine locks.

GET requires exact persisted and in-memory record agreement, current settlement,
namespace, host identity, boot and version, then syncs the directory before success.
It never infers acceptance from target equality or rolls memory back. A later claim,
start, restore or ownership change makes the receipt stale.

The named route is additive. Older daemons return 404 before effects; callers must
never fall back to PATCH. Fleet forwarding uses the existing machine route.
