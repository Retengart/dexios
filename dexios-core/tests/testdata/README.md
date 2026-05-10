# KDF Testdata Provenance

This directory contains checked-in reference vectors for the stable KDF surface
in `dexios-core/tests/key_derivation.rs`.

These vectors are intended to prove external correctness of the normal
`dexios_core::kdf::Kdf` API, not legacy Dexios file-format compatibility.
After Phase 3 Plan 03-01, that normal API derives only BLAKE3-Balloon keys.
Historical compatibility coverage for removed KDF tags stays in header/domain
tests instead of this vector set.

## Phase 3 KDF Policy

- BLAKE3-Balloon remains the normal V1 KDF for new encrypted files and new V1
  keyslots.
- Argon2id is removed from normal derivation and user-selectable creation
  paths.
- The historical V1 keyslot tag `[0xDF, 0x02]` remains parseable as
  `UnsupportedArgon2id` and workflow code maps it to `UnsupportedKdf` before
  attempting derivation.
- BLAKE3-Balloon parameters are frozen for Phase 3: space cost `278_528`, time
  cost `1`, p-cost `1`, output length `32`, and Balloon algorithm delta `3`.

## Source Policy

- Balloon vectors come from an independent Python implementation:
  `https://github.com/nachonavarro/balloon-hashing` at commit
  `8e28a7822113f1e8ef56b175550210c1a8e36c1a`, adapted locally to use Python
  `blake3` 1.0.8 as the hash primitive with `delta=3`.
- Context7 `/rustcrypto/password-hashes` documents the RustCrypto
  `balloon-hash` raw-output API used for password-derived key material. The
  same Context7 source documents Argon2id as a RustCrypto implementation API,
  not as a required Dexios file-format dependency after Phase 3 demotion.
- Local `balloon-hash` 0.4.0 source confirms `Params::new` takes
  `s_cost`, `t_cost`, and `p_cost`; its Balloon algorithm delta is a separate
  hardcoded constant.

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

The checked-in stable vectors were generated on 2026-03-07 with:

- password: `test-password`
- stable Balloon salt: `0x05` repeated 16 times
- current Dexios KDF parameter sets only

Stable BLAKE3-Balloon parameters:

- space 278528
- time 1
- p-cost 1
- delta 3
- output length 32

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
