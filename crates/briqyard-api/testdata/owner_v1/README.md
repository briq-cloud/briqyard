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

## sealed_owner_units_v1.vectors

A byte-for-byte copy of the shared unit-commitment vectors (owner-layer erratum 2 §4):
`infra/briqyard/execution/__fixtures__/sealed_owner_units_v1.vectors` in the API's repository, at the
draft commit `628b9a32a9c562a52336bd22ba8847ae2c7cf6d7` (B draft #896; it supersedes the 57-row file
`21371a4f…bdf3` and nothing else).

* Whole-file SHA-256: `8d317e519e8c0d216c462ddcc47f9e97a7a2694e31d0a03e685ca47452b29b72`, 43,765 bytes, 63
  LF-terminated rows, `name TAB kind TAB input TAB expected`. The input is JSON with sorted keys and no spaces.
* `expected` is a digest, `a:b:c:d` (four commitments of a unit), `accept`, or `refuse`.
* All values are public synthetic fixtures. The file is read, never regenerated or edited here; the
  native test reproduces every row and checks each refusal's reason
  (`sealed::tests::unit_vectors`).

## sealed_owner_inputs_v1.positive.json and sealed_owner_inputs_v1.positive-daemon-upgrade.json

Byte-for-byte copies of B's positive `Inputs` profiles (format `sealed.owner.inputs.positive/v2`),
from `infra/briqyard/execution/__fixtures__/` in the API's repository (draft #896). Each holds a
Plan and its canonical bytes, the canonical `native.inputs/v1` manifest, B-private policy values,
the raw operand bytes native's `DeploymentPolicy` compares (base64url with a declared length and
SHA-256), and B's expected digests, which are cross-checks only.

| File | Commit | Size | SHA-256 |
|---|---|---|---|
| `sealed_owner_inputs_v1.positive.json` | `09325ad317421f22f079738cbe9bb5100d4c254f` | 61,223 | `df13edca8dd6632f47662c157a3b2085dff45b79daf4541e4095fe6c664d3a8a` |
| `sealed_owner_inputs_v1.positive-daemon-upgrade.json` | `df4d6a88cbb6afc0f517e6915334f98e4bced5ea` | 61,178 | `014eeee72ab22bc8c21d931fb20b47fded709d28cdff0d3111d588c788aeacee` |

The first supersedes `0fa80799…` (shape-incompatible, never mirrored). Both are synthetic and
public, never edited here, and read only through `include_bytes!` in
`inputs::tests::companion`, which checks length and hash first.
