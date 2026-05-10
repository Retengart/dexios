# Dexios Safety Contract

## Purpose

This document is the tracked maintainer-facing safety contract for the Dexios
core and domain refactor. Later safety-sensitive phase plans must cite the
relevant invariant IDs below and show coverage by test, inspection, analysis,
or demonstration before they depend on changed behavior.

The contract describes desired safety invariants and records whether each
invariant is already proven by current source and tests, known to be broken, or
assigned to a later phase.

## Status Vocabulary

- `current`: current source and tests prove the invariant today.
- `broken`: desired safety invariant is currently violated; an ignored known-bug regression or source analysis records the gap.
- `future phase`: invariant is intentionally assigned to a later roadmap phase and not proven in Phase 1.

## Safety Invariant Matrix

| ID | Domain | Invariant | Status | Authority | Evidence | Requirement | Owner |
|----|--------|-----------|--------|-----------|----------|-------------|-------|
| FMT-001 | Headers | V1 header is 416 bytes. | current | Current source and tests | `dexios-core/src/header/common.rs`; `dexios-core/tests/v1_header.rs`; `book/src/dexios-core/Headers.md` | SAFE-01, VERI-02 | Phase 2 |
| FMT-002 | Headers | The first 32 V1 header bytes are authenticated as payload AAD. | current | Current source and tests | `dexios-core/src/header/v1.rs`; `dexios-core/tests/v1_header.rs`; `book/src/dexios-core/Headers.md` | SAFE-01, FORM-03 | Phase 2 |
| KDF-001 | KDFs | V1 KDF identifiers for `Blake3Balloon` and `Argon2id` are explicit. | current | Current source and docs | `dexios-core/src/header/v1.rs`; `book/src/dexios-core/Headers.md`; `dexios-core/tests/testdata/kdf_vectors.toml` | SAFE-01, KEY-04 | Phase 3 |
| STRM-001 | Stream encryption | Stream encryption authenticates header AAD and final chunks. | future phase | Current source and later stream tests | `dexios-core/src/stream.rs`; `book/src/dexios-core/Encryption.md`; final tamper regressions are assigned to Phase 3 | SAFE-01, CRYP-02, CRYP-03 | Phase 3 |
| KEY-001 | Key material | Committed encrypted artifacts should not end with zero usable keyslots. | broken | Current source analysis | `dexios-domain/src/key/delete.rs` removes the matching keyslot before writing the new header; a quarantined regression is assigned to Phase 1 Plan 01-03 | SAFE-01, KEY-01, KEY-02, VERI-01 | Phase 5 |
| STOR-001 | Storage writes | Existing final outputs should remain unchanged when an operation fails. | broken | Current source analysis | `dexios-domain/src/storage.rs`; `dexios/src/subcommands/encrypt.rs`; `dexios/src/subcommands/decrypt.rs`; a quarantined regression is assigned to Phase 1 Plan 01-04 | SAFE-01, STOR-01, STOR-02, VERI-01 | Phase 4 |
| STOR-002 | Path identity | Input/output path aliases should be rejected before final output handles open. | broken | Current source analysis | `dexios/src/subcommands/encrypt.rs` and `dexios/src/subcommands/decrypt.rs` reject equal strings but do not prove resolved path identity before opening outputs; a quarantined regression is assigned to Phase 1 Plan 01-04 | SAFE-01, STOR-03, VERI-01 | Phase 4 |
| ARCH-001 | Archive boundaries | Temporary ZIP artifacts are plaintext exposure and must not be described as secure erase. | current | Editable docs and current source | `book/src/technical-details/Secure-Erase.md`; `book/src/technical-details/Directory-Packing.md`; `dexios-domain/src/pack.rs`; `dexios-domain/src/unpack.rs` | SAFE-01, ARCH-04 | Phase 6 |
| ERR-001 | Error handling | Parse, authentication, path, IO, and commit failures should remain distinguishable enough for rollback and user data preservation. | future phase | Later typed-error work | Current source has broad workflow errors; typed rollback and preservation boundaries are assigned to Phase 5 | SAFE-01, ERR-01, ERR-02 | Phase 5 |
| DOC-001 | Documentation | Source-of-truth precedence is recorded by topic. | current | This contract | `docs/safety-contract.md` Source-of-Truth Matrix | SAFE-04 | Phase 1 |

## Source-of-Truth Matrix

The source-of-truth matrix records topic-specific authority when current source,
editable docs, generated docs, security policy, or historical specs disagree.

Generated docs are not authoritative over book/src and may drift until regenerated intentionally.

| Topic | Current Authority | Supporting Sources | Historical or Generated Sources | Phase 1 Decision |
|-------|-------------------|--------------------|---------------------------------|------------------|
| V1 header layout and AAD | Current source/tests plus `book/src/dexios-core/Headers.md` are the current authority. | `dexios-core/src/header/common.rs`; `dexios-core/src/header/v1.rs`; `dexios-core/tests/v1_header.rs`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` is historical input only; generated `docs/` is generated output. | Treat the 416-byte V1 header and first-32-byte AAD behavior as current only when source/tests prove it. |
| KDF identifiers and parameters | Current source, current KDF vectors, and `book/src/dexios-core/Headers.md` are the authority for V1 keyslot tags and KDF parameter evidence. | `dexios-core/src/header/v1.rs`; `dexios-core/src/kdf.rs`; `dexios-core/tests/key_derivation.rs`; `dexios-core/tests/testdata/kdf_vectors.toml`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` and generated `docs/` are comparison inputs only. | Preserve explicit V1 tags for `Blake3Balloon` and `Argon2id`; KDF default/compatibility decisions remain Phase 3 work. |
| stream encryption block/final semantics | Current source and `book/src/dexios-core/Encryption.md` describe current block, AAD, and final-block behavior. | `dexios-core/src/stream.rs`; `dexios-domain/src/encrypt.rs`; `dexios-domain/src/decrypt.rs`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` documents historical LE31 and final-block behavior but is not sole authority; generated `docs/` is generated output. | Keep STRM-001 as `future phase` until deterministic tamper/final-block tests prove the full invariant. |
| keyslot mutation safety | Current source and later owning-crate tests are the authority. | `dexios-domain/src/key/delete.rs`; `dexios-domain/tests/keyslots_v1.rs`. | Historical docs describe key deletion mechanics but do not prove final-keyslot safety; generated `docs/` is generated output. | Record final-keyslot deletion as a broken baseline under KEY-001 until Phase 5 fixes it and Phase 1 quarantined tests are unignored or replaced. |
| header dump/strip/restore | Current source and owning tests are the authority. | `dexios/src/subcommands/header.rs`; `dexios-domain/src/header/`; `book/src/dexios-core/Headers.md`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` is historical input; generated `docs/` is generated output. | Treat restore exactness and partial-read behavior as Phase 5 workflow work unless current tests directly prove the specific invariant. |
| pack/unpack archive boundaries | Current source/tests plus editable docs are the authority for ZIP boundary behavior and plaintext temp exposure. | `dexios-domain/src/pack.rs`; `dexios-domain/src/unpack.rs`; `dexios-domain/tests/unpack.rs`; `book/src/technical-details/Directory-Packing.md`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` contains older erase wording; generated `docs/` is generated output. | Archive redesign is deferred to Phase 6; Phase 1 records plaintext temp ZIP artifacts as exposure, not secure erase. |
| delete-after-success and secure erase wording | `book/src/technical-details/Secure-Erase.md` and current source/test behavior are current authority. | `dexios/src/subcommands/encrypt.rs`; `dexios/src/subcommands/decrypt.rs`; `dexios/src/subcommands/unpack.rs`; `dexios/src/subcommands/pack.rs`; `book/src/` editable documentation source. | Old erase claims in historical material are not current product claims; generated `docs/` is generated output. | Describe deletion as delete-after-success only; do not claim physical secure erase or sanitized plaintext temp artifacts. |
| error taxonomy and rollback decisions | Current source plus future typed-error tests are the authority. | `dexios-core/src/header/`; `dexios-core/src/stream.rs`; `dexios-domain/src/`; `dexios/src/subcommands/`. | Historical docs and generated `docs/` may explain user-facing behavior but do not establish rollback correctness. | Keep ERR-001 as `future phase` until Phase 5 distinguishes parse/auth/path/IO/commit failures enough for preservation decisions. |
| security reporting policy | `SECURITY.md` is the authority for reporting channels and supported versions. | Current repository policy and maintainer-facing security notes. | Generated `docs/` may copy policy text but does not override `SECURITY.md`. | Use `SECURITY.md` for vulnerability reporting claims; use source/tests/contracts for runtime safety behavior. |

## Known Broken Baselines

| Invariant | Broken baseline | Evidence | Fix owner |
|-----------|-----------------|----------|-----------|
| KEY-001 | Deleting the final usable keyslot can create an encrypted artifact with no usable keyslots. | Current source analysis in `dexios-domain/src/key/delete.rs`; quarantined regression planned in Phase 1 Plan 01-03. | Phase 5 |
| STOR-001 | Workflows can open and truncate existing final outputs before the operation has fully succeeded. | Current source analysis in CLI/domain storage output-open paths; quarantined regression planned in Phase 1 Plan 01-04. | Phase 4 |
| STOR-002 | Same-file checks are string-level in current CLI encrypt/decrypt paths and do not prove canonical, symlink, or hardlink identity before output handles open. | Current source analysis in `dexios/src/subcommands/encrypt.rs` and `dexios/src/subcommands/decrypt.rs`; quarantined regression planned in Phase 1 Plan 01-04. | Phase 4 |

## Fixture Baseline

Phase 1 fixture work must add reviewable fixture evidence for valid V1 files,
malformed V1 files, wrong-key cases, detached headers, and header/keyslot
mutation cases. Fixture rows must cite the owning invariant ID, provenance,
expected behavior, and owning future phase when a fixture demonstrates a broken
invariant.

## No-Unjustified-Unsafe Policy

`dexios-core/src/lib.rs` and `dexios-domain/src/lib.rs` must keep
`#![forbid(unsafe_code)]`. The Rust Reference describes `forbid` as identical
to `deny`, with the additional effect that later code cannot change the lint
level. That makes the crate-root lint the compiler-backed baseline for SAFE-03.

Any future exception requires all of these before acceptance:

1. a dedicated invariant row in `docs/safety-contract.md`;
2. a proof comment explaining why safe Rust cannot express the boundary;
3. an owning test boundary in the crate that uses the exception;
4. explicit maintainer review in the phase summary.

## Verification Gate

Phase plans that depend on these invariants must run the relevant focused tests
or inspection commands listed by each task, then include these commands:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --no-deps`
- `cargo test --workspace --all-features --release --verbose`
- `rg -n "#!\\[forbid\\(unsafe_code\\)\\]" dexios-core/src/lib.rs dexios-domain/src/lib.rs`
