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
| FMT-002 | Headers | The first 32 V1 header bytes are authenticated as payload AAD. | current | Current source and tests | `dexios-core/src/header/v1.rs`; `dexios-core/src/stream.rs::V1PayloadStream`; `dexios-core::header::V1HeaderAad`; `dexios-core/tests/v1_header.rs`; `book/src/dexios-core/Headers.md` | SAFE-01, FORM-03 | Phase 2 |
| FMT-003 | Headers | Header restore rejects short targets before writing or extending them. | current | Current source and tests | `dexios-domain/src/header/restore.rs`; `dexios-domain/tests/header_restore.rs::header_restore_rejects_short_target_without_writing` | FORM-04, FORM-05, VERI-01 | Phase 2 |
| FMT-004 | Headers | V1 reserved bytes are rejected when non-zero. | current | Reviewable byte fixture and core test | `dexios-core/tests/testdata/v1_malformed_reserved_byte.hex`; `dexios-core/tests/v1_header.rs::fixture_v1_malformed_reserved_byte_is_rejected` | SAFE-01, VERI-02 | Phase 2 |
| FMT-005 | Headers | Detached V1 header mode stores a parseable header separately from encrypted payload bytes. | current | CLI fixture test | `dexios/tests/header_details_cli.rs::detached_header_current_v1_fixture_keeps_header_separate` | SAFE-01, VERI-02 | Phase 2 |
| FMT-006 | Headers | Legacy header formats are rejected as unsupported format. | current | Current source and core test | `dexios-core/src/header/mod.rs`; `dexios-core/tests/v1_header.rs::read_header_rejects_legacy_prefix_as_unsupported_format` | SAFE-01, VERI-02 | Phase 2 |
| KDF-001 | KDFs | V1 normal KDF derivation is BLAKE3-Balloon only, while the historical Argon2id tag `[0xDF, 0x02]` is recognized as unsupported historical metadata. | current | Current source, tests, editable docs, and Context7 `/rustcrypto/password-hashes` research | `dexios-core/src/kdf.rs`; `dexios-core/src/header/v1.rs`; `dexios-domain/src/key.rs`; `dexios-core/tests/key_derivation.rs`; `dexios-core/tests/testdata/kdf_vectors.toml`; `dexios-domain/tests/keyslots_v1.rs`; `book/src/dexios-core/Headers.md`; `book/src/dexios-core/Password-Hashing.md` | SAFE-01, KEY-04, KEY-05 | Phase 3 |
| STRM-001 | Stream encryption | Typed V1 stream encryption authenticates header-derived AAD and final block state; failed decrypt output is uncommitted scratch until final authentication succeeds. | current | Current source, stream matrix tests, and editable docs | `dexios-core/src/stream.rs::V1PayloadStream`; `dexios-core/src/stream.rs::V1PayloadEncryptor`; `dexios-core/src/stream.rs::V1PayloadDecryptor`; `dexios-core/tests/stream_v1.rs`; `book/src/dexios-core/Encryption.md` | SAFE-01, CRYP-02, CRYP-03 | Phase 3 |
| KEY-001 | Key material | Committed encrypted artifacts should not end with zero usable keyslots. | current | Current source and tests | `dexios-core/src/header/v1.rs::V1Keyslots`; `dexios-domain/src/key/delete.rs`; `dexios-domain/tests/keyslots_v1.rs::key_del_rejects_final_keyslot_before_writing_header` | SAFE-01, KEY-01, KEY-02, VERI-01 | Phase 2 |
| KEY-002 | Key material | Wrong V1 keys fail verification and decryption before plaintext is accepted. | current | Domain generated fixture test | `dexios-domain/tests/keyslots_v1.rs::wrong_key_current_v1_fixture_rejects_verification_and_decrypt` | SAFE-01, VERI-02 | Phase 3 |
| KEY-003 | Key material | V1 count-changing keyslot mutation is rejected until the payload can be re-encrypted under the new header AAD; same-count key changes preserve decryption. | current | Domain generated fixture tests | `dexios-domain/tests/keyslots_v1.rs::key_add_rejects_v1_count_change_without_breaking_existing_decrypt`; `dexios-domain/tests/keyslots_v1.rs::can_change_and_reject_final_delete_v1_keyslots` | SAFE-01, VERI-02 | Phase 3 |
| SECR-001 | Secret handling | `Protected<T>` zeroizes on drop, redacts `Debug` as `[REDACTED]`, has no blanket clone or public direct exposure API, and exposes secrets only through closure-scoped `with_exposed`. | current | Current source, tests, editable docs, and Context7 `/rustcrypto/utils` zeroize research | `dexios-core/src/protected.rs`; `dexios-core/tests/protected.rs`; `book/src/dexios-core/Protected-Wrapper.md` | SECR-01, SECR-03, SECR-04 | Phase 3 |
| SECR-002 | Secret handling | CLI prompt password temporaries use `Zeroizing<String>` for direct, confirmation, mismatch, empty-input, and prompt-error paths; generated passphrase output is intentional disclosure and warns about terminal scrollback or logs. | current | Current CLI source, tests, editable docs, and Context7 `/rustcrypto/utils` zeroize research | `dexios/src/cli/prompt.rs`; `dexios/src/global/states.rs`; `book/src/technical-details/Keys.md` | SECR-02, SECR-04 | Phase 3 |
| STOR-001 | Storage writes | Existing final outputs remain unchanged until the operation, required staged output commits, and requested hash gates succeed. | current | Current source and real filesystem tests | `dexios-domain/src/storage/transaction.rs`; `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/tests/transactions.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios/tests/decrypt_cli_regressions.rs::decrypt_wrong_key_preserves_existing_output`; `dexios/tests/storage_transactions_cli.rs`; `dexios/tests/delete_source_cli.rs` | SAFE-01, STOR-01, STOR-02, STOR-04, STOR-06, VERI-01 | Phase 4 |
| STOR-002 | Path identity | Input/output/header path aliases are rejected by domain-owned identity checks before final output handles open. | current | Current source and real filesystem tests | `dexios-domain/src/storage/identity.rs`; `dexios-domain/tests/path_identity.rs`; `dexios/tests/encrypt_cli_regressions.rs::encrypt_rejects_same_file_alias_before_opening_output`; `dexios/tests/pack_cli_regressions.rs`; `dexios/tests/unpack_cli_regressions.rs`; `dexios/tests/storage_transactions_cli.rs` | SAFE-01, STOR-03, STOR-06, VERI-01 | Phase 4 |
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
| KDF identifiers and parameters | Current source, current KDF vectors, `book/src/dexios-core/Headers.md`, and `book/src/dexios-core/Password-Hashing.md` are the authority for V1 keyslot tags and KDF parameter evidence. | `dexios-core/src/header/v1.rs`; `dexios-core/src/kdf.rs`; `dexios-core/tests/key_derivation.rs`; `dexios-core/tests/testdata/kdf_vectors.toml`; `dexios-domain/tests/keyslots_v1.rs`; `book/src/` editable documentation source; Context7 `/rustcrypto/password-hashes` research. | `spec/specification-v1.pdf` and generated `docs/` are comparison inputs only. | Treat `[0xDF, 0x01]` as the BLAKE3-Balloon normal tag. Treat `[0xDF, 0x02]` as the unsupported historical Argon2id tag. Current BLAKE3-Balloon parameters are frozen: space cost `278_528`, time cost `1`, p-cost `1`, output length `32`, and delta `3`. |
| stream encryption block/final semantics | Current source, `dexios-core/tests/stream_v1.rs`, and `book/src/dexios-core/Encryption.md` describe current typed stream, header-derived AAD, uncommitted scratch, and final block behavior. | `dexios-core/src/stream.rs`; `dexios-core/tests/stream_v1.rs`; `dexios-domain/src/encrypt.rs`; `dexios-domain/src/decrypt.rs`; `book/src/` editable documentation source; Context7 `/rustcrypto/aeads` research. | `spec/specification-v1.pdf` documents historical LE31 and final-block behavior but is not sole authority; generated `docs/` is generated output. | Treat STRM-001 as current after Phase 3 stream matrix coverage. Do not infer Phase 4 storage transactions or final-output preservation from the core uncommitted-scratch contract. |
| keyslot mutation safety | Current source and owning-crate tests are the authority. | `dexios-core/src/header/v1.rs::V1Keyslots`; `dexios-domain/src/key/delete.rs`; `dexios-domain/tests/keyslots_v1.rs`. | Historical docs describe key deletion mechanics but do not prove final-keyslot safety; generated `docs/` is generated output. | Treat strict V1 keyslot cardinality and final-keyslot delete rejection as current Phase 2 behavior. |
| secret wrapper and CLI secret handling | Current source/tests plus `book/src/dexios-core/Protected-Wrapper.md` and `book/src/technical-details/Keys.md` are the authority for secret wrapper access, prompt temporaries, debug redaction, and generated passphrase disclosure. | `dexios-core/src/protected.rs`; `dexios-core/tests/protected.rs`; `dexios/src/cli/prompt.rs`; `dexios/src/global/states.rs`; `book/src/` editable documentation source; Context7 `/rustcrypto/utils` research. | Generated `docs/` is generated output and may lag until regenerated intentionally. | Treat `with_exposed` as the only public `Protected<T>` access path, no blanket `Protected<T>` clone as current behavior, prompt strings as `Zeroizing<String>` temporaries, and `--auto` passphrase display as intentional disclosure that can be captured by terminal scrollback or logs. |
| header dump/strip/restore | Current source and owning tests are the authority. | `dexios/src/subcommands/header.rs`; `dexios-domain/src/header/`; `dexios-domain/tests/header_restore.rs::header_restore_rejects_short_target_without_writing`; `book/src/dexios-core/Headers.md`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` is historical input; generated `docs/` is generated output. | Treat V1-only dump, strip, restore, and short-target rejection as current Phase 2 behavior; broader workflow request/error contracts remain Phase 5 work. |
| storage transactions and path identity | Current domain storage modules and real filesystem tests are the authority for Phase 4 final-output preservation, path identity, and cleanup sequencing. | `dexios-domain/src/storage/mod.rs`; `dexios-domain/src/storage/fs.rs`; `dexios-domain/src/storage/temp.rs`; `dexios-domain/src/storage/identity.rs`; `dexios-domain/src/storage/transaction.rs`; `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/src/storage/test_support.rs`; `dexios-domain/tests/transactions.rs`; `dexios-domain/tests/path_identity.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios/tests/storage_transactions_cli.rs`; `dexios/tests/delete_source_cli.rs`. | Historical direct-final-write behavior and generated docs do not override current source/tests. | Treat Phase 4 storage responsibilities as split by module: real filesystem storage, temporary artifacts, identity, transactions, cleanup receipts, and test failure hooks are separate maintainer evidence surfaces. |
| pack/unpack archive boundaries | Current source/tests plus editable docs are the authority for ZIP boundary behavior and plaintext temp exposure. | `dexios-domain/src/pack.rs`; `dexios-domain/src/unpack.rs`; `dexios-domain/tests/unpack.rs`; `book/src/technical-details/Directory-Packing.md`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` contains older erase wording; generated `docs/` is generated output. | Archive redesign is deferred to Phase 6; Phase 1 records plaintext temp ZIP artifacts as exposure, not secure erase. |
| delete-after-success and secure erase wording | `book/src/technical-details/Secure-Erase.md` and current source/test behavior are current authority. | `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios/src/subcommands/encrypt.rs`; `dexios/src/subcommands/decrypt.rs`; `dexios/src/subcommands/unpack.rs`; `dexios/src/subcommands/pack.rs`; `dexios/tests/delete_source_cli.rs`; `book/src/` editable documentation source. | Old erase claims in historical material are not current product claims; generated `docs/` is generated output. | Describe deletion as ordinary delete-after-success only: cleanup runs after transaction commit and requested hash success, reports cleanup failures distinctly, and does not claim physical secure erase or sanitized plaintext temp artifacts. |
| error taxonomy and rollback decisions | Current source plus future typed-error tests are the authority. | `dexios-core/src/header/`; `dexios-core/src/stream.rs`; `dexios-domain/src/`; `dexios/src/subcommands/`. | Historical docs and generated `docs/` may explain user-facing behavior but do not establish rollback correctness. | Keep ERR-001 as `future phase` until Phase 5 distinguishes parse/auth/path/IO/commit failures enough for preservation decisions. |
| security reporting policy | `SECURITY.md` is the authority for reporting channels and supported versions. | Current repository policy and maintainer-facing security notes. | Generated `docs/` may copy policy text but does not override `SECURITY.md`. | Use `SECURITY.md` for vulnerability reporting claims; use source/tests/contracts for runtime safety behavior. |

## Resolved Phase 1 Broken Baselines

The Phase 1 known-bug regressions remain named history for traceability, but Phase 4 made the storage invariants current and the tests are no longer ignored.

| Invariant | Former broken baseline | Current evidence | Fixed in |
|-----------|------------------------|------------------|----------|
| STOR-001 | output truncation on failure: workflows could open and truncate existing final outputs before the operation fully succeeded. | Domain transactions and cleanup receipts plus passing CLI regressions: `dexios-domain/src/storage/transaction.rs`; `dexios-domain/tests/transactions.rs`; `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios/tests/decrypt_cli_regressions.rs::decrypt_wrong_key_preserves_existing_output`; `dexios/tests/delete_source_cli.rs`. | Phase 4 |
| STOR-002 | same-file alias truncation: old CLI checks were string-level and did not prove canonical, relative, symlink, or hardlink identity before output handles opened. | Domain path identity graph plus passing real filesystem regressions: `dexios-domain/src/storage/identity.rs`; `dexios-domain/tests/path_identity.rs`; `dexios/tests/encrypt_cli_regressions.rs::encrypt_rejects_same_file_alias_before_opening_output`; `dexios/tests/pack_cli_regressions.rs`; `dexios/tests/unpack_cli_regressions.rs`. | Phase 4 |

## Fixture Baseline

Phase 1 fixture work uses `dexios-core/tests/testdata/fixture_manifest.toml` as
the manifest for reviewable byte fixtures and generated workflow fixtures.

| Fixture ID | Group | Evidence | Requirement | Invariant |
|------------|-------|----------|-------------|-----------|
| `v1-valid-single-keyslot` | `valid-v1` | `dexios-core/tests/testdata/v1_valid_single_keyslot.hex`; `dexios-core/tests/v1_header.rs::fixture_v1_valid_single_keyslot_roundtrips` | VERI-02 | FMT-001 |
| `v1-malformed-reserved-byte` | `malformed-v1` | `dexios-core/tests/testdata/v1_malformed_reserved_byte.hex`; `dexios-core/tests/v1_header.rs::fixture_v1_malformed_reserved_byte_is_rejected` | VERI-02 | FMT-004 |
| `wrong-key-current-v1` | `wrong-key` | `dexios-domain/tests/keyslots_v1.rs::wrong_key_current_v1_fixture_rejects_verification_and_decrypt` | VERI-02 | KEY-002 |
| `detached-header-current-v1` | `detached-header` | `dexios/tests/header_details_cli.rs::detached_header_current_v1_fixture_keeps_header_separate` | VERI-02 | FMT-005 |
| `keyslot-mutation-reject-count-change` | `keyslot-mutation` | `dexios-domain/tests/keyslots_v1.rs::key_add_rejects_v1_count_change_without_breaking_existing_decrypt`; `dexios-domain/tests/keyslots_v1.rs::can_change_and_reject_final_delete_v1_keyslots` | VERI-02 | KEY-003 |

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

Phase 3 closes with an additional KDF/stream/secret gate:

- stale normal Argon2id wording is rejected, while explicit historical unsupported Argon2id wording is allowed;
- targeted KDF, V1 header, V1 stream, protected wrapper, domain keyslot, CLI header-details, and CLI parser/prompt tests pass;
- workspace release and debug checks, rustfmt, clippy, full release tests, and no-unsafe crate-root checks pass.
