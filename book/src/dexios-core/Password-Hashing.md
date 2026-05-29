## Password Hashing

Dexios derives 32-byte wrapping keys from user-provided key material and a 16-byte salt.

The normal canonical V1 KDF contract supports one hashing family for new files
and new keyslots:

- `Argon2id`

`Argon2id` (RFC 9106) is the OWASP-recommended memory-hard password hashing
function. It replaces the retired `BLAKE3-Balloon` KDF for all new V1 keyslots.

## Current Defaults

For new files:

- `Argon2id` is the only normal KDF for new V1 keyslots
- KDF parameters are serialized as canonical profile ids, not
  user-configurable header knobs
- the historical Argon2id tag (a distinct unsupported keyslot profile pair) is
  no longer supported for new writes
- `argon2 0.5.3` is built with the `zeroize` feature enabled

For decryption and key manipulation, Dexios reads the required KDF family from
candidate keyslot metadata. Canonical V1 keyslots store a KDF profile id and KDF
parameter profile id. The historical Argon2id profile pair is recognized as
unsupported metadata and reported when the selected candidate requires it, when
all candidate keyslots are unsupported, or when a workflow preflight rejects
unsupported keyslot metadata before prompting. Mixed headers can still derive
against supported keyslots.

## Frozen Argon2id Parameters

The canonical V1 contract freezes the `Argon2id` parameters for the canonical
KDF param-profile id `0x01`:

- algorithm: `Argon2id`, version `0x13` (Argon2 v1.3)
- memory cost (`m_cost`): `262_144` KiB (256 MiB)
- time cost (`t_cost`): `4` passes
- parallelism (`p_cost`): `4` lanes
- output length: `32` bytes
- salt length: `16` bytes

The four lanes are computed sequentially in pure Rust (no threads), but the
resulting digest is spec-correct for the declared `p_cost`. The canonical V1
keyslot KDF profile ids are unchanged (KDF profile `0x01` / param-profile
`0x01`); they now denote `Argon2id`.

The checked KDF vector lives in `dexios-core/tests/testdata/kdf_vectors.toml`
and is exercised by `dexios-core/tests/key_derivation.rs`. The stable vector was
generated independently from the Argon2 reference C implementation (the `argon2`
CLI) and cross-checked against `argon2-cffi 25.1.0`; both agree, validating the
RustCrypto output at the frozen production parameters. Context7
`/rustcrypto/password-hashes` documents the raw-output `Argon2` API that writes
derived bytes into a caller-provided output buffer; Dexios uses that API.

The workspace manifest source-gates this dependency policy:

- `argon2 0.5.3` is the canonical KDF crate
- `argon2 = { version = "0.5.3", default-features = false, features = ["alloc", "zeroize"] }`

The enabled `zeroize` feature wipes Argon2's internal memory blocks on drop for
the locked crate version. This is a crate-internal allocation handling claim. It
is not a whole-process memory cleanup, allocator-history, swap, crash-dump,
terminal, shell-log, secure-erase, or physical-media sanitization guarantee.

`blake3` is no longer part of the KDF. It is retained only for content hashing
(the dexios-domain hasher and cleanup digests); `dexios-core` no longer depends
on `blake3`.

A single canonical `Argon2id` derive costs roughly `0.5s` on reference
hardware. KDF parameter changes require measured evidence from:

```bash
bash scripts/measure_performance_gate.sh --scenario kdf
```

The focused KDF measurement can enforce an opt-in local threshold with
`--max-kdf-seconds` or `DEXIOS_KDF_MAX_SECONDS`. The default maintainer gate
does not run this timing check.

The historical Argon2id tag (the distinct unsupported keyslot profile pair) is
now a file-format diagnosis only, not a required dependency or normal write
policy. It is not a normal write policy.

## Handling the Hash

Derived keys are wrapped in `Protected<>` and exposed only when initializing the cipher layer.

The implementation is intentionally explicit:

- raw key material is read into owned byte buffers
- the selected KDF derives a 32-byte value
- raw input access is scoped through the secret wrapper
- the derived key is only exposed to the encrypt/decrypt primitives
