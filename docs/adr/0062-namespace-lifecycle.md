# ADR 0062: Serialize namespace deletion with admission

Date: 2026-10-30 · Status: accepted

Namespace deletion checked for machines before asynchronously removing the bridge. A create
could enter after that check, leaving an admitted machine without its network.

A host-wide reader/writer gate orders namespace lifecycle operations. Creates, gateway puts,
moves (including renames), and quota puts hold shared admission. Deletion holds exclusive
admission from the empty check through gateway, bridge, DNS, and record teardown. Concurrent
admissions stay concurrent; a namespace deleted first is recreated before a new machine enters.

Gateway admission calls the already-admitted record helper rather than acquiring the reader
gate recursively. This avoids a deadlock when a deletion is queued between two reader locks.
The existing allocation lock still orders subnet allocation and namespace renames.

A deterministic regression pauses bridge deletion, polls a concurrent create at admission,
then verifies admission resumes only after teardown in the recreated namespace.
