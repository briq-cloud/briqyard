# 0069: Owned backup publication

Status: accepted. The child-ownership correction below is implemented independently of the
future host-local publication protocol. That protocol remains unavailable here.

## Child ownership

A backup's request is an observer, not the lifetime owner of its children or storage work.
`zfs send` and `zfs receive` use one retained supervisor. Registration precedes spawn. The
supervisor owns the exact child, transfer future and pipes, running marker and stderr drain.
It retains at most 64 KiB of stderr while continuously draining the rest.

Transfer failure or cancellation requests termination of only that owned child. Positive
wait/reap precedes rollback, destination cleanup, admission release and a settled reply.
`kill_on_drop` is defense in depth, not an exit receipt. A failed or blocked wait retains a
fenced owner and leaves drain incomplete. Ordinary ZFS commands also retain their actual
running owner when their caller stops observing them.

The Manager owns bounded backup, deletion and expiry jobs, including their turns and shared
active gate. Admission closes before handover; already admitted queued work may finish under
its retained scope. Create/restore admission is reserved before recording an accepted create and transferred
synchronously to its queued make worker. Record validation failure releases only a positively
undispatched reservation. Recovery reserves before partial-disk cleanup. Restore's make worker
retains its lifecycle lock and participates in the same I/O drain. Dropping a request waiter cannot drop these owners. Shutdown's existing
60-second budget bounds waiting, without claiming that unfinished work settled.

Storage formats, backup IDs, encryption and the successful legacy storage sequence stay
compatible. The correction changes failure/cancellation ownership, not publication predicates
or receipts. An acquired lock, an empty job map, elapsed time or a new daemon PID cannot
retroactively certify descendants orphaned by an older daemon.

## Further protocol gates

Complete host-local publication still requires durable generation admission, exact planned
capture names and observed GUIDs, encrypted manifest ordering, committed dependencies,
restart reconstruction, restore/delete exclusion, holder transitions and shared retained ZFS
mutation permits. A stream receipt alone must not commit its generation or release its pins.

An explicitly opted-in local mode must have a sticky parser fence and fail closed on unknown
or uncertain state. First activation requires a genuinely fresh supported source/creator
domain or separate positive historical creator and worker closure; fresh directories or a
configuration flag are insufficient. Existing-domain adoption is not enabled by this change.
Actual helper lifetime retention and Linux/filesystem/ZFS/crash/power-loss/historical-binary
qualification remain required before that mode can be enabled. Process termination is not a
power-loss test.

Fleet publication and qualified S3 publication are separate required integrations. No local
publication mode, S3 protocol, native configuration or automatic activation is added here.

## Native helper qualification

The ignored `zfs::owned_real_tests::native_owned_stream_roundtrip_and_failure_settlement`
case requires an operator-provisioned separate keyless file-vdev test pool. It validates the
exact nonce, pool/parent GUIDs, backing-file identity and inherited exclusive fixture lease
before creating only its own child datasets. It covers a noncompressible byte/hash roundtrip,
partial source-read failure and receiver input failures. Missing/foreign inputs refuse; the
test never creates/imports a pool or reads a key. Unresolved work or unexpected inventory
leaves fixtures for the operator. This qualifies helper settlement only, not encryption,
process-crash recovery, power-loss durability or publication activation.
