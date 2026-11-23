# Sealed v3.1 interop vectors

`vectors.json` holds the values SYL-268 interface revision 3.1 publishes (contract SHA-256
`de7b14d3…f5ac`). Nothing in it is computed by a consumer. The Ed25519 seeds are RFC 8032 section
7.1 tests 1 to 3: public test material that reproduces the contract's published signatures and
signs nothing real.

| Consumer | Run | Checks |
|---|---|---|
| Rust, `transition::tests::vectors_json` | `cargo test -p briqyard-api --features execution-admission` | the fixture equals what the Rust codec produces |
| `tests/interop/conformance.ts` | `node conformance.ts` (Node 22.18+, built-in crypto, no dependency) | 81 |
| `tests/interop/conformance.py` | `python3 -I conformance.py` (`cryptography`) | 81 |

Both consumers decode raw bytes with their own strict `C` parser and reproduce: the native
registration bytes, legacy `reg_hash`, ACK digest and the `H(Reg)` exception (C order is not the
native digest); the `query.host` bytes, preimage, signature and envelope hash with seven negative
envelopes; the trial, origin and command commitments, native request digest, approvals, issuance,
job, outcome, both status hashes, `final.read.trial`, `client.enable.trial` and the timeout rule;
the custody capture, matched and exited hashes. `SEALED_VECTORS=<path>` points either script at
another file.

## Coverage gaps

The contract publishes no bytes for these, so they have Rust structure tests but no cross-language
vector: Cut, Receipt, Gate, Guard, Intent, Witness, Ticket, Permit, ROk, Packet, HRead, ARead,
ApiView, the observe pair, Launch, LGrant, Death, Resume, Secrets, the client and trial3 control
envelopes, and the final read.

These need a runtime observation, not a digest fixture:

- `kcmp` on a real SCM_RIGHTS pidfd under actual UIDs, in the custodian's and authority's real
  sandboxes.
- The 5 s challenge, per-frame and 120 s exit deadlines, the 30 s permit window and the qualified
  clock interval: monotonic and database clocks.
- `Dims.bytes` and `fits`: the production snapshot serializer and native count predicates.
- Registration high-water lineage across the host, authority and API, and the durable
  commit-before-sign order of both owners.
- Strict Ed25519 point and scalar rejection: tested in Rust only; Node and Python verify the
  published signatures but are not claimed to refuse small-order or non-prime-subgroup points.
- The legacy `ProjectionEvidence` JSON of `P3/projection` and the native `ExecRequest` coordinator.
