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
| FMT-003 | Headers | Header restore rejects short targets, inexact detached headers, and non-stripped targets before writing or extending them. | current | Current source and tests | `dexios-domain/src/header/restore.rs`; `dexios-domain/tests/header_restore.rs::header_restore_rejects_short_target_without_writing`; `dexios/tests/header_cli_regressions.rs::header_restore_rejects_inexact_headers_and_invalid_targets_without_mutation`; `dexios/tests/workflow_error_cli.rs::header_exact_failures_use_typed_cli_mapping` | FORM-04, FORM-05, VERI-01 | Phase 5 |
| FMT-004 | Headers | V1 reserved bytes are rejected when non-zero. | current | Reviewable byte fixture and core test | `dexios-core/tests/testdata/v1_malformed_reserved_byte.hex`; `dexios-core/tests/v1_header.rs::fixture_v1_malformed_reserved_byte_is_rejected` | SAFE-01, VERI-02 | Phase 2 |
| FMT-005 | Headers | Detached V1 header mode stores a parseable 416-byte header separately from encrypted payload bytes; header dump writes exactly one V1 header and rejects header-only artifacts. | current | Current source and CLI fixture tests | `dexios-domain/src/header/dump.rs`; `dexios-domain/src/header/strip.rs`; `dexios/tests/header_details_cli.rs::detached_header_current_v1_fixture_keeps_header_separate`; `dexios/tests/header_cli_regressions.rs::header_dump_rejects_header_only_input_and_writes_exact_detached_header`; `dexios/tests/header_cli_regressions.rs::header_strip_rejects_header_only_input_and_preserves_payload_bytes`; `dexios/tests/workflow_error_cli.rs::header_exact_failures_use_typed_cli_mapping` | SAFE-01, FORM-05, VERI-02 | Phase 5 |
| FMT-006 | Headers | Legacy header formats are rejected as unsupported format. | current | Current source and core test | `dexios-core/src/header/mod.rs`; `dexios-core/tests/v1_header.rs::read_header_rejects_legacy_prefix_as_unsupported_format` | SAFE-01, VERI-02 | Phase 2 |
| KDF-001 | KDFs | V1 normal KDF derivation is BLAKE3-Balloon only; `balloon-hash 0.4.0` is built with the `zeroize` feature; the historical Argon2id tag `[0xDF, 0x02]` is recognized as unsupported historical metadata. | current | Current source, tests, editable docs, and Context7 `/rustcrypto/password-hashes` research | `Cargo.toml`; `Cargo.lock`; `dexios-core/src/kdf.rs`; `dexios-core/src/header/v1.rs`; `dexios-domain/src/key.rs`; `dexios-core/tests/key_derivation.rs`; `dexios-core/tests/testdata/kdf_vectors.toml`; `dexios-domain/tests/keyslots_v1.rs`; `book/src/dexios-core/Headers.md`; `book/src/dexios-core/Password-Hashing.md` | SAFE-01, KEY-04, KEY-05, KDF-01, KDF-05 | Phase 3 / Phase 9 |
| STRM-001 | Stream encryption | Typed V1 stream encryption authenticates header-derived AAD and final block state; failed decrypt output is uncommitted scratch until final authentication succeeds. | current | Current source, stream matrix tests, and editable docs | `dexios-core/src/stream.rs::V1PayloadStream`; `dexios-core/src/stream.rs::V1PayloadEncryptor`; `dexios-core/src/stream.rs::V1PayloadDecryptor`; `dexios-core/tests/stream_v1.rs`; `book/src/dexios-core/Encryption.md` | SAFE-01, CRYP-02, CRYP-03 | Phase 3 |
| KEY-001 | Key material | Committed encrypted artifacts do not end with zero usable keyslots; key deletion removes only the old-key-proven slot. | current | Current source and tests | `dexios-core/src/header/v1.rs::V1Keyslots`; `dexios-domain/src/key/delete.rs`; `dexios-domain/tests/keyslots_v1.rs::key_del_rejects_final_keyslot_before_writing_header`; `dexios-domain/tests/keyslots_v1.rs::key_delete_removes_only_old_key_proven_slot_and_preserves_payload`; `dexios/tests/key_cli_regressions.rs::key_delete_maps_failures_without_remaining_key_collection` | SAFE-01, KEY-01, KEY-02, VERI-01 | Phase 5 |
| KEY-002 | Key material | Wrong V1 keys fail verification and decryption before plaintext is accepted or committed. | current | Domain and CLI tests | `dexios-domain/tests/keyslots_v1.rs::wrong_key_current_v1_fixture_rejects_verification_and_decrypt`; `dexios/tests/decrypt_cli_regressions.rs::decrypt_wrong_key_preserves_existing_output`; `dexios/tests/workflow_error_cli.rs::incorrect_key_and_unsupported_workflow_messages_stay_terse`; `dexios/tests/workflow_error_cli.rs::key_verify_wrong_key_and_unsupported_kdf_use_typed_mapping` | SAFE-01, KEY-02, VERI-02 | Phase 5 |
| KEY-003 | Key material | V1 key add remains unsupported without mutation; key change preserves payload bytes and proves the replacement key unwraps the same master key before commit. | current | Domain generated fixture tests | `dexios-domain/tests/keyslots_v1.rs::key_add_rejects_v1_count_change_without_breaking_existing_decrypt`; `dexios-domain/tests/keyslots_v1.rs::key_add_intent_rejects_supported_v1_without_mutating_header_or_payload`; `dexios-domain/tests/keyslots_v1.rs::key_change_commits_replacement_header_that_only_new_key_can_use`; `dexios-domain/tests/keyslots_v1.rs::can_change_and_reject_final_delete_v1_keyslots`; `dexios/tests/key_cli_regressions.rs::key_change_reads_new_key_after_old_key_verification_succeeds` | SAFE-01, KEY-02, VERI-02 | Phase 5 |
| SECR-001 | Secret handling | `Protected<T>` zeroizes on drop, redacts `Debug` as `[REDACTED]`, has no blanket clone or public direct exposure API, and exposes secrets only through closure-scoped `with_exposed`. | current | Current source, tests, editable docs, and Context7 `/rustcrypto/utils` zeroize research | `dexios-core/src/protected.rs`; `dexios-core/tests/protected.rs`; `book/src/dexios-core/Protected-Wrapper.md` | SECR-01, SECR-03, SECR-04 | Phase 3 |
| SECR-002 | Secret handling | CLI prompt password temporaries use `Zeroizing<String>` for direct, confirmation, mismatch, empty-input, and prompt-error paths; generated passphrase output is intentional disclosure and warns about terminal scrollback or logs; invalid explicit `--auto` word counts are rejected before generation and disclosure. | current | Current CLI source, tests, editable docs, and Context7 `/rustcrypto/utils` zeroize research | `dexios/src/cli/prompt.rs`; `dexios/src/cli.rs`; `dexios/src/global/states.rs`; `scripts/verify_cli_surface.sh`; `book/src/technical-details/Keys.md` | SECR-02, SECR-04, KDF-03, KDF-04 | Phase 3 / Phase 9 |
| STOR-001 | Storage writes | Existing final outputs remain unchanged until the operation, required staged output commits, and requested hash gates succeed. | current | Current source and real filesystem tests | `dexios-domain/src/storage/transaction.rs`; `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/tests/transactions.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios/tests/decrypt_cli_regressions.rs::decrypt_wrong_key_preserves_existing_output`; `dexios/tests/storage_transactions_cli.rs`; `dexios/tests/delete_source_cli.rs` | SAFE-01, STOR-01, STOR-02, STOR-04, STOR-06, VERI-01 | Phase 4 |
| STOR-002 | Path identity | Input/output/header path aliases are rejected by domain-owned identity checks before final output handles open. | current | Current source and real filesystem tests | `dexios-domain/src/storage/identity.rs`; `dexios-domain/tests/path_identity.rs`; `dexios/tests/encrypt_cli_regressions.rs::encrypt_rejects_same_file_alias_before_opening_output`; `dexios/tests/pack_cli_regressions.rs`; `dexios/tests/unpack_cli_regressions.rs`; `dexios/tests/storage_transactions_cli.rs` | SAFE-01, STOR-03, STOR-06, VERI-01 | Phase 4 |
| ARCH-001 | Archive boundaries | Temporary ZIP artifacts are plaintext exposure, archive structure is bounded by `ArchiveLimits`, and pack/unpack must not be described as secure erase. | current | Current source, real filesystem tests, and editable docs | `dexios-domain/src/archive.rs`; `dexios-domain/src/pack.rs`; `dexios-domain/src/unpack.rs`; `dexios-domain/tests/pack_paths.rs`; `dexios-domain/tests/unpack.rs`; `dexios/tests/pack_cli_regressions.rs`; `dexios/tests/unpack_cli_regressions.rs`; `book/src/technical-details/Directory-Packing.md`; `book/src/technical-details/Secure-Erase.md` | SAFE-01, ARCH-04, ARCH-05, VERI-03 | Phase 6 |
| ERR-001 | Error handling | Parse, authentication, path, IO, unsupported workflow, unsafe path, and commit failures remain distinguishable enough for rollback and user data preservation in encrypt, decrypt, header, and key workflows. | current | Current source and tests | `dexios-domain/src/workflow_error.rs`; `dexios-domain/tests/workflow_errors.rs`; `dexios-domain/tests/workflow_public_api.rs`; `dexios/src/subcommands/errors.rs`; `dexios/tests/workflow_error_cli.rs`; source gates in Phase 05 Plan 08 | SAFE-01, ERR-01, ERR-02, ERR-03, ERR-04 | Phase 5 |
| API-001 | Domain API and diagnostics | Public unpack construction uses checked `UnpackIntent`, storage failure hooks are gated behind `test-support` outside the default production API, typed `WorkflowErrorClass` remains the CLI mapping boundary, and domain errors preserve safe diagnostic `source()` chains. | current | Current source, source gates, focused tests, and CLI tests | `dexios-domain/src/unpack.rs`; `dexios/src/subcommands/unpack.rs`; `dexios-domain/src/storage/mod.rs`; `dexios-domain/src/storage/identity.rs`; `dexios-domain/src/storage/transaction.rs`; `dexios-domain/src/storage/temp.rs`; `dexios-domain/tests/workflow_public_api.rs`; `dexios-domain/tests/archive_public_api.rs`; `dexios-domain/tests/workflow_errors.rs`; `dexios-domain/tests/transactions.rs`; `dexios/tests/workflow_error_cli.rs`; `dexios/tests/verification_gate_docs.rs` | API-01, API-02, API-03, API-04, API-05 | Phase 10 |
| DOC-001 | Documentation | Source-of-truth precedence is recorded by topic. | current | This contract | `book/src/Safety-Contract.md` Source-of-Truth Matrix | SAFE-04 | Phase 1 |

## Source-of-Truth Matrix

The source-of-truth matrix records topic-specific authority when current source,
editable docs, generated docs, security policy, or historical specs disagree.

Generated docs are not authoritative over book/src and may drift until regenerated intentionally.

| Topic | Current Authority | Supporting Sources | Historical or Generated Sources | Phase 1 Decision |
|-------|-------------------|--------------------|---------------------------------|------------------|
| V1 header layout and AAD | Current source/tests plus `book/src/dexios-core/Headers.md` are the current authority. | `dexios-core/src/header/common.rs`; `dexios-core/src/header/v1.rs`; `dexios-core/tests/v1_header.rs`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` is historical input only; generated `docs/` is generated output. | Treat the 416-byte V1 header and first-32-byte AAD behavior as current only when source/tests prove it. |
| KDF identifiers and parameters | Current source, current KDF vectors, `book/src/dexios-core/Headers.md`, and `book/src/dexios-core/Password-Hashing.md` are the authority for V1 keyslot tags, dependency feature policy, and KDF parameter evidence. | `Cargo.toml`; `Cargo.lock`; `dexios-core/src/header/v1.rs`; `dexios-core/src/kdf.rs`; `dexios-core/tests/key_derivation.rs`; `dexios-core/tests/testdata/kdf_vectors.toml`; `dexios-domain/tests/keyslots_v1.rs`; `book/src/` editable documentation source; Context7 `/rustcrypto/password-hashes` research. | `spec/specification-v1.pdf` and generated `docs/` are comparison inputs only. | Treat `[0xDF, 0x01]` as the BLAKE3-Balloon normal tag. Treat `[0xDF, 0x02]` as the unsupported historical Argon2id tag. Current BLAKE3-Balloon parameters are frozen: space cost `278_528`, time cost `1`, p-cost `1`, output length `32`, and delta `3`. `balloon-hash 0.4.0` must keep the `zeroize` feature unless a later dependency proof replaces this policy. |
| stream encryption block/final semantics | Current source, `dexios-core/tests/stream_v1.rs`, and `book/src/dexios-core/Encryption.md` describe current typed stream, header-derived AAD, uncommitted scratch, and final block behavior. | `dexios-core/src/stream.rs`; `dexios-core/tests/stream_v1.rs`; `dexios-domain/src/encrypt.rs`; `dexios-domain/src/decrypt.rs`; `book/src/` editable documentation source; Context7 `/rustcrypto/aeads` research. | `spec/specification-v1.pdf` documents historical LE31 and final-block behavior but is not sole authority; generated `docs/` is generated output. | Treat STRM-001 as current after Phase 3 stream matrix coverage. Do not infer Phase 4 storage transactions or final-output preservation from the core uncommitted-scratch contract. |
| keyslot mutation safety | Current source and owning-crate tests are the authority. | `dexios-core/src/header/v1.rs::V1Keyslots`; `dexios-domain/src/key/delete.rs`; `dexios-domain/tests/keyslots_v1.rs`. | Historical docs describe key deletion mechanics but do not prove final-keyslot safety; generated `docs/` is generated output. | Treat strict V1 keyslot cardinality and final-keyslot delete rejection as current Phase 2 behavior. |
| secret wrapper and CLI secret handling | Current source/tests plus `book/src/dexios-core/Protected-Wrapper.md` and `book/src/technical-details/Keys.md` are the authority for secret wrapper access, prompt temporaries, debug redaction, generated passphrase validation, and generated passphrase disclosure. | `dexios-core/src/protected.rs`; `dexios-core/tests/protected.rs`; `dexios/src/cli.rs`; `dexios/src/cli/prompt.rs`; `dexios/src/global/states.rs`; `scripts/verify_cli_surface.sh`; `book/src/` editable documentation source; Context7 `/rustcrypto/utils` research. | Generated `docs/` is generated output and may lag until regenerated intentionally. | Treat `with_exposed` as the only public `Protected<T>` access path, no blanket `Protected<T>` clone as current behavior, prompt strings as `Zeroizing<String>` temporaries, explicit invalid `--auto` counts as fail-before-generation errors, and successful `--auto` passphrase display as intentional disclosure that can be captured by terminal scrollback or logs. |
| header dump/strip/restore | Current source and owning tests are the authority. | `dexios/src/subcommands/header.rs`; `dexios-domain/src/header/`; `dexios-domain/tests/header_restore.rs`; `dexios/tests/header_cli_regressions.rs`; `dexios/tests/workflow_error_cli.rs`; `book/src/dexios-core/Headers.md`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` is historical input; generated `docs/` is generated output. | Treat V1-only dump, strip, restore, exact detached-header length, header-only rejection, missing-payload rejection, stripped-target validation, and typed header workflow errors as current Phase 5 behavior. |
| storage transactions and path identity | Current domain storage modules and real filesystem tests are the authority for Phase 4 final-output preservation, path identity, cleanup sequencing, and Phase 10 storage test-support gating. | `dexios-domain/src/storage/mod.rs`; `dexios-domain/src/storage/fs.rs`; `dexios-domain/src/storage/temp.rs`; `dexios-domain/src/storage/identity.rs`; `dexios-domain/src/storage/transaction.rs`; `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/src/storage/test_support.rs`; `dexios-domain/tests/transactions.rs`; `dexios-domain/tests/path_identity.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios-domain/tests/workflow_public_api.rs`; `dexios/tests/storage_transactions_cli.rs`; `dexios/tests/delete_source_cli.rs`. | Historical direct-final-write behavior and generated docs do not override current source/tests. | Treat Phase 4 storage responsibilities as split by module: real filesystem storage, temporary artifacts, identity, transactions, cleanup receipts, and test failure hooks are separate maintainer evidence surfaces. Failure-hook entry points are test-support scoped; public receipt and identity evidence remains production API. |
| pack/unpack archive boundaries | Current source/tests plus editable docs are the authority for checked unpack construction, ZIP boundary behavior, plaintext temp exposure, Zstd-by-default offline archival framing, minimal metadata preservation, and structural archive limits. | `dexios-domain/src/archive.rs`; `dexios-domain/src/pack.rs`; `dexios-domain/src/unpack.rs`; `dexios/src/subcommands/unpack.rs`; `dexios-domain/tests/pack_paths.rs`; `dexios-domain/tests/unpack.rs`; `dexios-domain/tests/archive_public_api.rs`; `dexios/tests/pack_cli_regressions.rs`; `dexios/tests/unpack_cli_regressions.rs`; `book/src/technical-details/Directory-Packing.md`; `book/src/technical-details/Secure-Erase.md`; `book/src/` editable documentation source. | `spec/specification-v1.pdf` contains older erase wording; generated `docs/` is generated output. | Treat `UnpackIntent` as the public checked unpack boundary. Treat temporary ZIP artifacts as ordinary plaintext exposure, not secure erase. Treat `ArchiveLimits` as the current structural policy: 100000 entries, 4096 normalized path bytes, and 64 normalized path components. |
| delete-after-success and secure erase wording | `book/src/technical-details/Secure-Erase.md` and current source/test behavior are current authority. | `dexios-domain/src/storage/cleanup.rs`; `dexios-domain/tests/cleanup_receipts.rs`; `dexios/src/subcommands/encrypt.rs`; `dexios/src/subcommands/decrypt.rs`; `dexios/src/subcommands/unpack.rs`; `dexios/src/subcommands/pack.rs`; `dexios/tests/delete_source_cli.rs`; `book/src/` editable documentation source. | Old erase claims in historical material are not current product claims; generated `docs/` is generated output. | Describe deletion as ordinary delete-after-success only: cleanup runs after transaction commit and requested hash success, reports cleanup failures distinctly, and does not claim physical secure erase or sanitized plaintext temp artifacts. |
| error taxonomy and rollback decisions | Current source plus typed-error, diagnostic source-chain, and CLI mapping tests are the authority. | `dexios-domain/src/workflow_error.rs`; `dexios-domain/src/encrypt.rs`; `dexios-domain/src/decrypt.rs`; `dexios-domain/src/pack.rs`; `dexios-domain/src/unpack.rs`; `dexios-domain/src/header.rs`; `dexios-domain/src/key.rs`; `dexios-domain/src/storage/mod.rs`; `dexios-domain/src/storage/identity.rs`; `dexios-domain/src/storage/transaction.rs`; `dexios-domain/tests/workflow_errors.rs`; `dexios-domain/tests/workflow_public_api.rs`; `dexios/src/subcommands/errors.rs`; `dexios/tests/workflow_error_cli.rs`. | Historical docs and generated `docs/` may explain user-facing behavior but do not establish rollback correctness. | Treat `WorkflowErrorClass` as the typed CLI mapping boundary. Treat `std::error::Error::source()` chains as diagnostics only; they add maintainer/debug depth and are not printed by default CLI errors. |
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

`dexios/src/main.rs`, `dexios-core/src/lib.rs`, and
`dexios-domain/src/lib.rs` must keep `#![forbid(unsafe_code)]`. The Rust
Reference describes `forbid` as identical to `deny`, with the additional
effect that later code cannot change the lint level. That makes the crate-root
lint the compiler-backed baseline for SAFE-03.

Any future exception requires all of these before acceptance:

1. a dedicated invariant row in `book/src/Safety-Contract.md`;
2. a proof comment explaining why safe Rust cannot express the boundary;
3. an owning test boundary in the crate that uses the exception;
4. explicit maintainer review in the phase summary.

## Verification Gate

This section is the Maintainer Verification Gate for safety-sensitive changes.
Phase plans and pull requests that depend on the invariants in this contract
must run the relevant focused tests or inspection commands listed by the
changed invariant first, then run the broad gate below before the change is
accepted.

For local verification, use:

- `bash scripts/verify_phase_gate.sh`

VERI-04 broad-gate rule: the minimum maintainer gate includes:

- no-unsafe crate-root checks for `dexios/src/main.rs`, `dexios-core/src/lib.rs`, and `dexios-domain/src/lib.rs`
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --no-deps`
- `cargo test --workspace --all-features --release --verbose`
- `cargo audit --deny warnings`
- `cargo deny check`
- `cargo build -p dexios --profile release-lto`
- `bash scripts/verify_cli_surface.sh`
- `mdbook build`
- `git diff --exit-code -- docs`
- `bash scripts/verify_repo_hygiene.sh`
- `git diff --check`

The gate fails before long-running checks if required tools are missing. Local
setup remains explicit: install `cargo-audit` with
`cargo install cargo-audit --locked --version 0.22.1`, install `cargo-deny`
with `cargo install cargo-deny --locked --version 0.19.6`, and install
`mdbook` with `cargo install mdbook --locked`. The gate prints these install
hints but does not auto-install tools.

VERI-06 release-note rule: breaking changes to file format behavior, CLI
behavior, security claims, or compatibility boundaries must update
`CHANGELOG.md` under `## Unreleased`. Use the `### Breaking Changes`,
`### Security`, `### Verification`, or `### Documentation` headings as
appropriate for the change.

`local-notes/` is local-only working context. It must remain ignored by git and
must not be required to understand public release notes, user documentation, or
maintainer verification steps.

VERI-05 measured-check rule: default changes to KDF cost, stream throughput,
pack/unpack memory behavior, archive structural limits, or temp-space
assumptions must run `scripts/measure_performance_gate.sh --scenario <name>`
and record the command, fixture shape, hardware profile, platform, and summary
result. KDF release checks may enforce an opt-in local budget with
`--max-kdf-seconds` or `DEXIOS_KDF_MAX_SECONDS`. If a category is not
applicable, record the not applicable reason explicitly.
`scripts/measure_performance_gate.sh` remains a focused release gate for KDF,
stream, archive, and temp-space changes; it is not part of the default
`scripts/verify_phase_gate.sh` maintainer gate.

Phase 9 closes with an additional KDF/passphrase/secret-memory gate:

- `balloon-hash 0.4.0` keeps the `zeroize` feature and `blake3 = "=1.8.3"` stays pinned;
- explicit invalid `--auto` word counts fail before passphrase generation and disclosure;
- KDF timing evidence records a hardware profile and may use `--max-kdf-seconds` or `DEXIOS_KDF_MAX_SECONDS` for focused release checks;
- narrow secret-memory claim documentation stays limited to owned-value zeroization, redacted debug output, `Zeroizing<String>` prompt temporaries, and closure-scoped `with_exposed`.

Phase 3 closes with an additional KDF/stream/secret gate:

- stale normal Argon2id wording is rejected, while explicit historical unsupported Argon2id wording is allowed;
- targeted KDF, V1 header, V1 stream, protected wrapper, domain keyslot, CLI header-details, and CLI parser/prompt tests pass;
- workspace release and debug checks, rustfmt, clippy, full release tests, and no-unsafe crate-root checks pass.
