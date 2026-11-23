# ADR 0147: A closed, non-authorizing reader for native.inputs/v1

Date: 2026-11-23 · Status: accepted

## Context

Interface v3.6 (SYL-268, SHA-256 f74ffc23fc71d58dd76f77a250fde8ffc29fe81e302a3417a7a7615391f72b42)
freezes the `native.inputs/v1` manifest and, through v3.3 (SHA-256
277f9521a73c798b4966c624ff13356b5b109ca68664777fa9052077d3feec50), the `native.closure/v1`
child. The manifest names public locators and commitments of one operation: both releases, the
topology, the actors, the two resources' paths and digests, the closure. No reader existed, so
each later package would have parsed it differently. Both documents stay frozen: this ADR
adds no field, default or format.

## Decisions

**Grammar and meaning are separate.** `decode::<Inputs>` (the existing canonical codec) checks
the closed grammar: one bounded canonical UTF-8 object, explicit nulls, unknown, duplicate,
missing or unsorted fields refused, plus every invariant a field type cannot hold. Those are
version, commit, path, text and DER forms; strictly sorted unique regions, hosts, actors and
peers; the one-to-one registered/intrinsic map; the single host row matching `registered` and
`x.host`; the fixed guard and control socket per role; one shared boot for the native processes;
distinct TLS identities; a peer endpoint's bracketed host is an IPv6 literal that `Ipv6Addr` parses
and that is already in its canonical text (aliases such as `[::A]` or `[0:0:0:0:0:0:0:1]` refuse, none is
rewritten); a port, in a peer or in the continuation URL, is explicit unpadded decimal in
1..=65535; the serving floor surviving the target leaving; the closure's
`x` equal to the manifest's. Actors sort by lexical wire name (`A,B,H,R,gateway,installer`), not
by Rust enum order.

**Binding compares, it does not choose.** `Inputs::bind(bytes, &Plan, &DeploymentPolicy)` returns a
`BoundInputs`, the only way to make one. It requires the Plan's `inputs` digest to be the hash of
the exact manifest bytes, then compares each field with the independent owner of that fact
(the Plan, the explicit release selections, per-actor observations, the daemon and authority
resource policies, topology and closure policy). A fact has one owner: a swap between the daemon
and the authority, a stale custodian, a second candidate or a changed listener order refuses.
Nothing is defaulted from the manifest, a path, DNS or the environment.

**Both custodians are the source daemon binary (v3.6 §3).** Each `Resource.custodian` must equal
the caller's custodian observation, run `source_release.daemon`, and carry the independently
approved `DeploymentPolicy.source_daemon_build`, which must also be `Plan.pre_d.build`. The
custodian's owner is a `ProcessOwner`: a typed value whose only constructor takes the measured
uid and gid and keeps them. The reader compares both to 0; a missing observation or any other
owner refuses. The caller is the independently trusted OS observer and owns that measurement;
nothing here reads `/proc`, infers an owner from a Plan, or defaults to root. A manifest, policy
and Plan that agree with one another on the wrong image or build still refuse.

**Member digests are unique and never a closure credential (v3.1 §34, v3.3 §1).**
`Plan.validate` refuses any repeated non-null digest among the old and new `hi, he, ni, ng, tr`.
The absent legacy `tr` stays valid. `bind` also refuses any old or new member equal to
`continuation.bearer`, `admin_host` or `admin_fleet`, besides the three being distinct from
one another. This is a comparison of the digests in hand; it is not a credential ledger.

**Release bytes are checked over supplied bytes only.** `VerifiedRelease::validate` takes the pin
file, the checksum list and the three assets as slices. The pin file is the closed five-field
shape of the historical 0.2.15 reference (`release`, `commit`, `releaseId`, `sha256`,
`source`); duplicate, unknown and missing keys refuse, `source` must be the tag URL of its own
version, and the pin digest covers the raw bytes, final LF included. The checksum list must hash to
the pinned digest and hold each binary exactly once; unrelated official entries neither matter
nor confer a right. Each asset must hash to its pinned digest. Selecting a tag, fetching,
and reading a file are outside this reader.

**Nothing here authorizes.** There is no approval, proof, permit or start. `BoundInputs` says
the manifest agrees with what its owners supplied, no more. Callers keep their own gates.

**One more regression, not a change: Death's commitment.** `Cut.custody` and `Launch.death`
consume `H(Death) = h(C(Death))`. Two tests in the existing transition suites show that this
equals an independent SHA-256 of the canonical bytes and that `h(C({"wire": Death}))` differs and is
refused by `Cut::check_death` and `Launch::check_death`. Neither check changed.

Narrow reading: v3.3 compares endpoints as literal text, so this reader keeps exact-input
equality and rejects malformed or non-canonical syntax. It adds no normalization and no
fallback. The continuation host stays a DNS-style name; it takes no bracketed literal.

## Test scope

Fixtures are synthetic (`testdata/native_inputs_v1`; `assemble.py` is a simple public reference
assembler, run twice with identical output, `inputs.json` SHA-256
c23eb41a9b34458d92c9983de496604fb622dca38912b84813914880f09e0d1c). The historical pin is a
shape reference only. This is not native qualification, an independent cross-language writer
run or proof of any real host fact.

## Consequences

The writer, the real owners' observations and the daemon wiring that consume `BoundInputs` stay
separate packages. Reopen if v3.6 or v3.3 changes.
