# owner_v1 golden

`sealed_owner_v1.golden` is a byte-for-byte copy of the public synthetic vector set the receiver
(R) and the API (B) already agree on: `infra/briqyard/execution/__fixtures__/sealed_owner_v1.golden`
at the commit whose subject ends "(golden 3e14f6a7)" on the receiver's main line.

* Whole-file SHA-256: `3e14f6a769042dae6e17fbea5c83ca8ac99d3c6057c5cd7fd5624a577aae9337`.
* One line per record: `name TAB sha256(record) TAB canonical JSON`. `test.rk.public` and
  `test.bk.public` carry only public keys (the third column); the corresponding seeds are not in
  this repository.
* Every value is synthetic: hosts, digests, process identities and keys are fixtures, not real
  material.

The native tests decode each record with the native wire types, check that it re-encodes to the
same bytes and hash, verify the three signed records under those public keys, and rebuild the
collector's answers from the target's own owner state. The file is read, never regenerated here.
