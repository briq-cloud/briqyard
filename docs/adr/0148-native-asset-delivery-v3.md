# ADR 0148: Native asset delivery v3, the suffix and typed secret acquisition

Date: 2026-11-23 · Status: guard-side primitive implemented; no startup caller, no closure
reader, no projection of `native.inputs` onto the requirements and pins, and no production
provisioning yet

## Context

Interface v3.3 (SYL-268, SHA-256 277f9521a73c798b4966c624ff13356b5b109ca68664777fa9052077d3feec50)
replaces the H 13-right and A 16-right asset selectors with one `native.prepare/v3` then
`native.assets/v3` conversation for both resources and appends the closed delivery table
after the unchanged prefix. v3.4 (4691a05d98969847c1bbeb592f71e3fadbf3a2f603bcfd33dac6b7d47ad9a9fe)
fixes the Hk and Ak payload as exactly 32 raw RFC 8032 seed octets and keeps the 83-byte PKCS#8
form for the ordinary authority key at A index 15 only. This ADR records what the guard-side
artifact layer (`execution_custody/artifacts*`, `sealed_input*`) chose to implement them.

## Decisions

**One ABI, no negotiation.** The prepare packet is `{"format":"native.prepare/v3"}` and the offer
`native.assets/v3`. A v1, v2, mixed or unknown selector fails to decode. The offer carries at most
22 rights (`MAX_ASSET_RIGHTS`), checked before the layout comparison; the socket owner sizes its
ancillary buffer from the same constant.

| Index | H | A | Descriptor beyond `class,bytes` | Payload and the check that owns it |
| --- | --- | --- | --- | --- |
| 0..=12 | prefix | 0..=14 (+ ordinary key at 15) | unchanged | unchanged; the Hk and Ak seed is now exactly 32 octets |
| next | `verification-registry` | same | `digest` | exact public bytes, the sealed registry grammar, closed profile |
| | `transition-server-cert` | same | `digest` | one DER leaf, the transport's closed profile for a server |
| | `transition-server-key` | same | `spki` | unencrypted PKCS#8 P-256; SPKI derived from the parsed key |
| | `transition-client-cert` | same | `digest` | as the server leaf, client role |
| | `transition-client-key` | same | `spki` | as the server key |
| | | `continuation-bearer` | `digest` | 1..=4096 bytes 0x21..=0x7e |
| | `daemon-api-cert`, `daemon-api-key` iff admin TLS | | `digest`, `spki` | key as above; the leaf is one complete ordinary DER object whose SPKI is the key's and neither transition identity's (no transition SAN or EKU) |
| | `backup-s3-pair` iff S3 | | `digest` | `C({access,secret})`, each strict unpadded base64url of 1..=4096 graphic bytes |
| | `local-pool-key` iff file key | | `key_id` | 64 lowercase hex; id from `briqyard_api::poolkey::id` |

A has exactly 22 rights; H has 18 + 2·admin_tls + s3 + file_key, at most 22. Suffix rights can
never shift a prefix index or the ordinary key.

**The caller states the optional rights.** `Requirements::Daemon{admin_tls, backup_s3, file_key}`
or `Requirements::Authority` is an input to `AssetOffer::decode`, `BoundAssets::bind` and the
suffix pins. It must come from the validated closure and the effective frozen config; a missing
file or credential is never evidence that a feature is off. The `native.inputs` reader exists
(ADR 0147) and is independently reviewed, but nothing projects its validated `Inputs` onto the
requirements and the pins, so the caller supplies both. `SuffixPins` mirrors the closure
fields one to one and is the single place that projection will fill; its option presence must
equal the requirements.

**Private payloads have typed readers only.** `read_small` refuses the ordinary key, both signer
seeds, the three suffix TLS keys, the bearer, the S3 pair and the pool key. Each has one
accessor returning only its validated material (`EvidenceSigner`, `TlsPrivateKey`,
`ContinuationBearer`, `BackupS3Credentials`, `PoolFileKey`), with a redacted `Debug`, no
`Clone`, no serialization and no raw `Vec`. These are not a generic secret type: each class has
its own. `EvidenceSigner` implements the existing `Signer` trait over Ed25519 and nothing
else. No new authorization field, grant or effect tag exists.

**Never trust an advertised field.** Each acquisition re-derives from the bytes in the
descriptor: seed to public key, PKCS#8 key to SPKI digest, pool key to id. The Hk/Ak public key
must equal the offer's and the Plan pin, itself a strict Ed25519 point through
`PinnedKey::new`; `Sig::sign` and `Sig::verify` keep their strict subgroup checks. The
descriptor holds a digest of public or digest-pinned bytes only; no private byte is hashed
for the descriptor (`spki` and `key_id` derive from public values).

**No descriptor leaves the crate.** `BoundAssets::artifact`, `descriptor_env` and the
`AsFd` of a `FrozenArtifact` are `pub(crate)`: only the transfer and exec code of this crate
sees a raw descriptor, and every public consumer gets a typed value or public bytes. Four
`compile_fail` doctests name the old getters and a positive doctest per type shows the same
imports compile. This is an API boundary, not isolation from malicious code in the same process.

**One validator per format.**

| Shared | Where | Change |
| --- | --- | --- |
| X.509 profile, `Name`, `Pair` | `briqyard_api::execution::private_cert` | relocated verbatim from the fleet transport, which re-exports it; its tests still run against it |
| `key_spki_digest` | same | new: the transport's own `ring` PKCS#8 parse, then the SPKI of the derived point |
| registry JSON, ordinary file | `briqyard_api::execution::provision::registry` | the parse inside `Config::load`, extracted unchanged and still tolerant (a missing `authority` is none; a positional row is accepted) |
| registry JSON, sealed | `provision::sealed_registry` | a dedicated grammar: an array of one to 32 objects of exactly `kid`, `role`, `issuer`, `authority`, `public_key`; `authority` explicit (a missing field is not a null), `role` only the string scalar `"authority"` or `"central"` (serde's object form is refused), no positional row, no unknown or duplicate field. Same `VerificationKey`; the closed profile stays in `secret.rs` |
| DER readers | `private_cert` | every temporary or nested reader (extension list, SAN, EKU, basic constraints) now has to be exhausted at both levels; `leaf_spki_digest` is the typed schema decode of `x509-cert` (pinned `=0.3.0`, `default-features = false`, the newest release that builds on the workspace compiler) for one complete ordinary leaf: no trailing byte, every X.509 field present (an empty validity is refused), and no trust, chain, name, usage or clock check. The profile parser stays the transition one |
| pool key id | `briqyard_api::poolkey::id` | used as is, after the exact lowercase check |

**Where pins are compared.** Bind (receipt) checks length, metadata, digest and profile, that each
transition leaf and key form one identity, that the two are distinct, and, with admin TLS, that
the daemon API leaf's SPKI is the actual private key's and equals neither transition SPKI.
`Plan::validate` requires `Plan.ordinary_key == Plan.pre_record.public_key` (v3.2 §17), so every
canonical decode of a Plan, including the profile check of the Plan descriptor at slot zero of
the receipt, refuses a violation before any private payload is read. `SealedInput::decode` then
adds the Plan pins and the Hk/Ak derivation, and
requires that the registry's one authority entry is the registered predecessor and that no
central key equals the Plan's Hk, Ak, Bk or Rk. `check_suffix_pins` compares the closure's
digests, pairs, server name and optional rights.

**One stage deadline.** `BoundAssets::bind`, `SealedInput::decode` and `check_suffix_pins`
take the caller's single `StageDeadline`; none opens a fresh frame, and each checks it again
after its last parse. The refusal under an already expired deadline is a deterministic test;
that the final check refuses a deadline expiring between the last read and the return is time
dependent and has no deterministic test. `freeze_signer` and `freeze_tls_key` read the key
back from the sealed descriptor and compare it with the advertised field, as the ordinary key
already did.

## Not decided or not done here

- No startup entry, candidate-side adoption, source provisioner or closure parser. The source side
  has `freeze_signer`, `freeze_tls_key` and `freeze_pool_key` taking the advertised field; the
  caller passes the Plan pin.
- Certificate validity needs the qualified clock and is checked where the identity is consumed
  (`LocalIdentity`). The daemon API leaf is checked for structure and key agreement only; its
  name, validity and trust belong to the ordinary TLS constructor.
- The central issuer and the central key set are not bound to anything. The Plan has no
  issuer field and no enrolled central inventory exists here, so only the grammar, the closed
  profile, uniqueness and the non-collision with the Plan's own keys are checked. That the
  registry's central set is the independently enrolled one remains the owner's proof; a digest
  of the bytes is not that proof.
- The local checks establish that the bytes agree with the descriptors, the Plan and the
  pins handed in. An independent check of those pins' content against the enrolled closure is
  a later owner's step and is not claimed.
- The prefix TLS key (index 12) keeps its generic digest-pinned read.
- Clearing is best effort. `ring`, the JSON decoder and the OS keep copies this code cannot
  erase; nothing here claims the bytes are gone from memory.
- All fixtures are synthetic. No native host test, release or deployment is claimed.
