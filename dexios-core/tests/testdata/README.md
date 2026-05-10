# KDF Testdata Provenance

This directory contains checked-in reference vectors for the stable KDF surface
in `dexios-core/tests/key_derivation.rs`.

These vectors are intended to prove external correctness of the new canonical
`dexios_core::kdf::Kdf` API, not legacy Dexios file-format compatibility.
Legacy compatibility coverage stays in the remaining header/domain tests until
later tasks remove the old format paths entirely.

## Source Policy

- Argon2id vectors come from an independent Python path:
  `argon2-cffi` 25.1.0 using `argon2.low_level.hash_secret_raw(Type.ID)`.
- Balloon vectors come from an independent Python implementation:
  `https://github.com/nachonavarro/balloon-hashing` at commit
  `8e28a7822113f1e8ef56b175550210c1a8e36c1a`, adapted locally to use Python
  `blake3` 1.0.8 as the hash primitive with `delta=3`.

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
- stable Argon2id salt: `0x03` repeated 16 times
- stable Balloon salt: `0x05` repeated 16 times
- current Dexios KDF parameter sets only

Stable Argon2id parameters:

- memory 262144 KiB
- time 10
- parallelism 4
- output length 32

Stable BLAKE3-Balloon parameters:

- space 278528
- time 1
- delta 3

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
