# KDF Testdata Provenance

This directory contains checked-in reference vectors for the stable KDF surface
in `dexios-core/tests/key_derivation.rs`.

These vectors are intended to prove external correctness of the normal
`dexios_core::kdf::Kdf` API, not legacy Dexios file-format compatibility.
That normal API derives only `Argon2id` keys (the `argon2id-stable` vector).
Historical compatibility coverage for removed KDF tags stays in header/domain
tests instead of this vector set.

## KDF Policy

- `Argon2id` (RFC 9106) is the normal V1 KDF for new encrypted files and new V1
  keyslots. It replaces the retired BLAKE3-Balloon KDF.
- The historical V1 keyslot tag `[0xDF, 0x02]` remains parseable as
  `UnsupportedArgon2id` and workflow code maps it to `UnsupportedKdf` before
  attempting derivation.
- Argon2id parameters are frozen for canonical V1: m_cost `262_144` KiB
  (256 MiB), t_cost `4` passes, p_cost `4` lanes, output length `32` bytes, salt
  length `16` bytes, and Argon2 version `0x13` (decimal `19`).

## Source Policy

- The `argon2id-stable` vector is generated independently of the Dexios
  implementation from two reference sources that must agree:
  - the Argon2 reference C implementation (the `argon2` CLI from
    `https://github.com/P-H-C/phc-winner-argon2`), and
  - `argon2-cffi 25.1.0` (Python `low_level.hash_secret_raw`, `Type.ID`).
- Both reference implementations produced the identical digest, independently
  validating the RustCrypto `argon2 0.5.3` output at the frozen production
  parameters. RustCrypto's own output is therefore cross-checked, never used as
  its own source of truth.

## Phase 1 Fixture Corpus Policy

Phase 1 fixture data uses disposable keys and non-secret payloads only. Byte
fixtures are stored as reviewable text formats by default, and generated
workflow fixtures must be tied to a manifest row with purpose, expected
behavior, owning invariant, and owner phase.

When a fixture is used as correctness evidence, its provenance must be
independent enough for the claim being made. Fixtures generated from current
Dexios code can document current compatibility behavior, but they must not be
treated as independent cryptographic or format truth unless a separate source
or reviewable byte fixture supports the same claim.

## Generation Notes

The checked-in stable vector was generated on 2026-05-29 with:

- password: `test-password`
- salt: `0123456789abcdef` (16 printable ASCII bytes, hex
  `30313233343536373839616263646566`)
- the frozen canonical Argon2id parameters only

Reproduce with the stock `argon2` CLI:

```bash
printf 'test-password' | argon2 '0123456789abcdef' -id -t 4 -m 18 -p 4 -l 32 -r
```

(`-m 18` selects `2^18 = 262144` KiB.) Cross-check with `argon2-cffi 25.1.0`:

```python
from argon2.low_level import hash_secret_raw, Type
hash_secret_raw(b"test-password", b"0123456789abcdef",
                time_cost=4, memory_cost=262144, parallelism=4,
                hash_len=32, type=Type.ID).hex()
```

Stable Argon2id parameters:

- m_cost 262144 KiB (256 MiB)
- t_cost 4
- p_cost 4
- version 0x13 (19)
- output length 32
- salt length 16

## Update Policy

- Do not regenerate vectors from the current Dexios implementation and then
  treat them as independent truth.
- Do not add version-tagged vectors back into this file.
- Any vector change must explain:
  - why the previous provenance is no longer acceptable
  - what independent source produced the new values
  - how to reproduce the generation path manually

## Why These Vectors Exist

These vectors catch:

- KDF parameter drift in the new canonical API
- salt or password handling regressions
- unexpected upstream behavior changes

They do not replace Dexios backward-compatibility fixtures.
