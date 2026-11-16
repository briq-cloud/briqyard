# 0140: Qualify named clones through the native fleet

The upgrade suite previously exercised sandbox seeds with explicit resources.
That does not establish the named init/service template contract: omitted size
must reach inheritance, and snapshot provenance uses the daemon's intrinsic ID
while placement uses its registered fleet ID.

Run a separate contract phase after forward-upgrade checks and before rollback.
Use the installed target binaries without rebuilding them. Temporarily enable
the two named profiles with the target init digest, then restore the configuration
even when the phase fails. These two daemon handovers are outside the measured
upgrade interval; original VMM identities must survive them.
Use SIGUSR2 and observe a new ready daemon for both transitions. A systemd restart
sends SIGTERM, which intentionally suspends ordinary guests rather than handing
their running VMMs to the replacement (ADR 0027).

For each profile, create and seal a builder through the fleet. Clone with omitted,
zero/default and matching resources; require inherited resources, active memory
origin and successful guest execution. Reject mismatched size, omitted/default
cold-create resources, malformed explicit size and sandbox snapshots used as named
templates. Require registered `local` routing and distinct intrinsic provenance.

The Python caller sends each mutation once. Lost responses fail qualification;
cleanup discovers only this attempt's namespace and random metadata marker, then
deletes its machines without replaying creates. Cleanup failures also fail the
suite. Existing sandbox sources and unrelated machines are preserved.

Offline fixtures cover wire shapes, refusal predicates, uncertain responses,
partial cleanup and configuration failure. Only the disposable native run
qualifies the actual artifacts and guest execution.
