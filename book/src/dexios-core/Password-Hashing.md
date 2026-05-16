## Password Hashing

Dexios derives 32-byte wrapping keys from user-provided key material and a 16-byte salt.

The normal canonical V1 KDF contract supports one hashing family for new files
and new keyslots:

- `BLAKE3-Balloon`

## Current Defaults

For new files:

- `Blake3Balloon` is the only normal KDF selector
- KDF parameters are serialized as canonical profile ids, not
  user-configurable header knobs
- the historical Argon2id tag is no longer supported for new writes
- `balloon-hash 0.4.0` is built with the `zeroize` feature enabled

For decryption and key manipulation, Dexios reads the required KDF family from the current keyslot metadata.
Canonical V1 keyslots store a KDF profile id and KDF parameter profile id. The
historical Argon2id profile pair is recognized as unsupported metadata and
reported before any key derivation attempt.

## Frozen BLAKE3-Balloon Parameters

Phase 3 freezes the BLAKE3-Balloon contract for canonical V1 output:

- space cost: `278_528`
- time cost: `1`
- p-cost: `1`
- output length: `32` bytes
- Balloon algorithm delta: `3`

The p-cost is the value passed to `balloon_hash::Params::new`. The delta is a
separate Balloon algorithm constant recorded in the vector metadata.

The checked KDF vector lives in `dexios-core/tests/testdata/kdf_vectors.toml`
and is exercised by `dexios-core/tests/key_derivation.rs`. Context7
`/rustcrypto/password-hashes` documents the raw-output `Balloon` API that writes
derived bytes into a caller-provided output buffer; Dexios uses that API with
BLAKE3 as the Balloon hash primitive.

The workspace manifest source-gates this dependency policy:

- `balloon-hash = { version = "0.4.0", features = ["zeroize"] }`
- `blake3 = "=1.8.3"`

The enabled `zeroize` feature covers `balloon-hash`'s internal allocated memory
buffer for the locked crate version. This is a crate-internal allocation
handling claim. It is not a whole-process memory cleanup, allocator-history,
swap, crash-dump, terminal, shell-log, secure-erase, or physical-media
sanitization guarantee.

KDF parameter changes require measured evidence from:

```bash
bash scripts/measure_performance_gate.sh --scenario kdf
```

The focused KDF measurement can enforce an opt-in local threshold with
`--max-kdf-seconds` or `DEXIOS_KDF_MAX_SECONDS`. The default maintainer gate
does not run this timing check.

The same Context7 `/rustcrypto/password-hashes` source documents historical
unsupported Argon2id as a RustCrypto implementation API. In Dexios, historical
Argon2id metadata is now a file-format diagnosis only, not a required dependency
or normal write policy.

## Handling the Hash

Derived keys are wrapped in `Protected<>` and exposed only when initializing the cipher layer.

The implementation is intentionally explicit:

- raw key material is read into owned byte buffers
- the selected KDF derives a 32-byte value
- raw input access is scoped through the secret wrapper
- the derived key is only exposed to the encrypt/decrypt primitives
