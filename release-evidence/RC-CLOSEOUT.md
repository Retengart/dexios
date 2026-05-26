# Dexios v3.0 Release Candidate Closeout Evidence

This document names the verification contracts and evidence for the v3.0 release candidate.
It records command names and structural evidence and does not claim proof of completion;
use a completed gate log or current `bash scripts/verify_phase_gate.sh` run for pass/fail
evidence. Each section records what was checked and under what conditions; no assertion is
made that every condition holds on every platform or in every build environment.

## Blocker-to-Check Traceability Matrix

This matrix maps every v3.0 blocker family to concrete regression tests, docs/source gates,
CI/release checks, and audit/hygiene checks. Each row records the evidence that keeps the
corresponding blocker class closed; it does not assert that the checks passed on every
platform or build run. Use a current `bash scripts/verify_phase_gate.sh` run for pass/fail
evidence.

| Blocker ID | Failure Class | Regression Test(s) | Docs/Source Gate(s) | CI/Release Check(s) | Audit/Hygiene Check(s) |
|------------|--------------|-------------------|--------------------|--------------------|----------------------|
| PATH-01..04 | symlink/parent-prefix rejection | `dexios-domain/tests/path_identity.rs`, `dexios-domain/tests/unpack.rs`, `dexios/tests/pack_cli_regressions.rs`, `dexios/tests/unpack_cli_regressions.rs` | `book/src/Safety-Contract.md` STOR-002 | `unit_tests.yml` (linux/macos/windows) | `verify_repo_hygiene.sh` |
| DASI-01..04 | delete-after-success cleanup | `dexios-domain/tests/cleanup_receipts.rs`, `dexios/tests/delete_source_cli.rs` | `book/src/technical-details/Secure-Erase.md`, `book/src/Safety-Contract.md` STOR-004 | `dexios-tests.yml` | `verify_repo_hygiene.sh` |
| DETP-01..04 | detached partial pair | `dexios-domain/tests/detached_publication.rs`, `dexios/tests/encrypt_cli_regressions.rs`, `dexios/tests/pack_cli_regressions.rs` | `book/src/Safety-Contract.md` STOR-005 | `dexios-tests.yml` | `verify_repo_hygiene.sh` |
| HDRM-01..04 | header/key mutation freshness | `dexios-domain/tests/header_restore.rs`, `dexios-domain/tests/keyslots_v1.rs`, `dexios/tests/header_cli_regressions.rs`, `dexios/tests/key_cli_regressions.rs` | `book/src/Safety-Contract.md` STOR-006 | `unit_tests.yml` | `verify_repo_hygiene.sh` |
| APIF-01..04 | public API footguns | `dexios-core/tests/public_api_footguns.rs`, `dexios-domain/tests/workflow_public_api.rs`, `dexios-domain/tests/archive_public_api.rs` | `book/src/Safety-Contract.md` API-002 | `unit_tests.yml` | `verify_repo_hygiene.sh` |
| DOCS-01..04 | documentation/spec fidelity | `dexios/tests/verification_gate_docs.rs` (55+ tests, phases 14-20) | All `book/src/*.md` source gates | `docs.yml`, `cargo-build.yml` | `verify_repo_hygiene.sh`, `cargo audit --deny warnings`, `cargo deny check` |
| CIGR-01..05 | CI/release gate hardening | `dexios/tests/verification_gate_docs.rs` Phase 21 tests: `phase21_locked_flag_and_lockfile_gate_are_source_gated` (CIGR-01), `phase21_permissions_and_job_ordering_are_source_gated` (CIGR-02 / D-09 / D-10), `phase21_tool_version_pins_are_source_gated` + `phase21_release_workflow_tool_pins_and_locked_build_are_source_gated` (CIGR-03), `phase21_release_workflow_asset_set_contract_is_source_gated` (CIGR-04), `phase21_windows_ci_coverage_is_source_gated` (CIGR-05) | `book/src/Safety-Contract.md`, `book/src/Installing-and-Building.md` | `release.yml` (`validate_tag -> maintainer_gate -> build -> publish`), `unit_tests.yml` (windows-latest) | `cargo audit --deny warnings`, `cargo deny check`, `verify_repo_hygiene.sh` |
| RCEV-01..05 | RC evidence stream | this document + `scripts/verify_phase_gate.sh` + `phase21_rc_closeout_artifact_is_present_and_source_gated` | `release-evidence/RC-CLOSEOUT.md` (this file) | `release.yml` maintainer_gate step | `verify_repo_hygiene.sh` |

### RCEV-02 Regression Coverage: 8 Reproduced Failure Classes

Each of the 8 reproduced failure classes from RCEV-02 has regression test coverage. The
table below records the class, covered status, and the specific test(s) that close it.

| Failure Class | Status | Concrete Test(s) |
|--------------|--------|-----------------|
| Symlink delete | Covered | `cleanup_receipt_from_processed_source_refuses_replaced_file` in `dexios-domain/tests/cleanup_receipts.rs` |
| Symlinked-parent output | Covered | `unpack_rejects_symlinked_output_directory_prefix` in `dexios-domain/tests/unpack.rs`; `identity_rejects_existing_roles_with_symlinked_parent_prefixes` in `dexios-domain/tests/path_identity.rs` |
| Detached partial pair | Covered | `dexios-domain/tests/detached_publication.rs`; `phase17_detached_payload_header_publication_is_source_gated` in `dexios/tests/verification_gate_docs.rs` |
| Header mutation race | Covered | `dexios-domain/tests/header_restore.rs` tests; `phase18_*` tests in `dexios/tests/verification_gate_docs.rs` |
| Stale docs | Covered | 55+ existing source-gate tests (phases 14-20) in `dexios/tests/verification_gate_docs.rs` |
| Generated docs drift | Covered | `phase20_pdf_freshness_commands_are_source_gated` in `dexios/tests/verification_gate_docs.rs`; docs freshness check in `scripts/verify_phase_gate.sh` |
| Release asset gaps | Covered | `phase21_release_workflow_asset_set_contract_is_source_gated` in `dexios/tests/verification_gate_docs.rs` (Phase 21 closes complete-set enforcement per D-04/D-05) |
| Public API footguns | Covered | `dexios-core/tests/public_api_footguns.rs`, `dexios-domain/tests/workflow_public_api.rs`, `dexios-domain/tests/archive_public_api.rs`, `phase19_*` tests in `dexios/tests/verification_gate_docs.rs` |

Note on audit/hygiene checks (D-03): `cargo audit --deny warnings` and `cargo deny check` are
mandatory in both the maintainer gate (`scripts/verify_phase_gate.sh`) and the release workflow
(`release.yml`). The weekly schedule in `audit.yml` is defense-in-depth only; the mandatory
checks run on every gate invocation, not on a schedule. The DOCS and CIGR rows record these
as the audit/hygiene checks that keep each blocker closed.

Note on docs/spec freshness (D-06): Docs and spec artifacts (mdBook HTML and Typst PDF) are
validated as maintainer-gate freshness evidence only (diff-clean mdBook build, deterministic
Typst compile with `--creation-timestamp 0`). They are not published as release binary assets.
The matrix records docs/spec freshness as a gate, not as part of the published asset-set contract.

## Accepted Residual Risks

- **ordinary (non-secure-erase) deletion:** Cleanup uses `std::fs::remove_file` /
  `std::fs::remove_dir_all`, which perform ordinary filesystem deletion rather than physical
  media sanitization. Files removed by delete-after-success are unlinked from the directory
  tree; overwrite behaviour depends on the filesystem and OS. No claim is made that this
  erases data from physical storage.

- **Unpack plaintext temporary exposure:** The V1 unpack architecture requires a seekable
  plaintext temporary ZIP before entry extraction. This exposure is documented in
  `book/src/technical-details/Secure-Erase.md` and bounded to the filesystem and the unpack
  duration. It is not eliminated.

- **Detached partial publication:** Detached-header mode reports errors with evidence when
  partial publication occurs; it does not perform recovery or rollback of already-committed
  artifacts. The failure class is error-with-evidence, not silent data loss.

- **Windows filesystem identity:** Windows filesystem identity uses `GetFileInformationByHandle`
  (volume serial + file index) rather than POSIX `(dev, ino)` pairs. Symlink rejection on
  Windows uses `std::os::windows::fs` file attribute checks rather than `lstat`. These are
  weaker than Unix. Build-only Windows support is named explicitly here, not implied by
  cross-platform identity claims.

## Platform Limits

- **Symlink rejection tests:** Symlink rejection tests use Unix-only POSIX `lstat` semantics
  (`std::os::unix::fs::symlink`). The `#[cfg(unix)]` arms in
  `dexios-domain/tests/path_identity.rs`, `dexios-domain/tests/cleanup_receipts.rs`,
  `dexios-domain/tests/header_restore.rs`, and `dexios-domain/tests/keyslots_v1.rs` are
  excluded on Windows by design — this is the honest behaviour, not a test gap.

- **Same-inode identity:** Unix same-inode identity uses the `(dev, ino)` pair from POSIX
  `libc::stat`. Windows identity uses volume serial number + file index via
  `GetFileInformationByHandle`, which covers the common case but has documented edge cases
  around hardlinks and certain virtual filesystems. Same-inode mutation detection is weaker
  on Windows.

- **Hardlink detection:** Hardlink detection uses `same_file::is_same_file` (backed by
  `libc stat` on Unix and `GetFileInformationByHandle` on Windows). The Unix path is
  well-tested; the Windows equivalent has known edge cases with virtual filesystems and
  network mounts.

## Non-Goals

- **Bit-for-bit reproducible builds:** Dexios does not claim reproducible builds. Build
  metadata, toolchain version, and linker flags affect the output binary. Reproducibility
  infrastructure is deferred to future milestone scope.

- **SBOM completeness or supply-chain prevention:** No Software Bill of Materials is
  generated or attested. Supply-chain hardening beyond `cargo deny` policy and `cargo audit`
  advisory scanning is deferred to ASR-02 and is out of scope for v3.0.

- **Secure erase or physical media sanitization:** Dexios deletion uses ordinary filesystem
  `unlink` operations. No overwrite pass, secure-delete primitive, or physical sanitization
  is performed or claimed.

- **V2 format redesign:** A V2 file format is deferred to FMT-01 and is out of scope for
  v3.0. The current V1 format is the only supported format.

- **Broad fuzz/property infrastructure (deferred to ASR-01):** Broad fuzz corpus maintenance,
  libfuzzer integration, and property-testing infrastructure across all parsers are deferred
  to ASR-01. Phase 21 assessed targeted proptest for archive path normalization and concluded
  existing example tests cover the known traversal sequences; no proptest was added.

- **Signed artifact attestations (deferred to ASR-02):** Signed release artifacts, SLSA
  provenance attestations, and keyless signing via Sigstore are deferred to ASR-02 and are
  out of scope for v3.0.

## Property and Fuzz Coverage Decision (RCEV-03)

Targeted proptest was evaluated for all five high-risk parsing and normalization boundaries
identified in Phase 21 research. The verdict for each boundary:

| Boundary | Existing Coverage | Proptest Adds Value? | Verdict |
|----------|-------------------|---------------------|---------|
| V1 header/AAD parse | `dexios-core/tests/stream_v1.rs` + `dexios-core/tests/v1_header.rs` + assurance-replay fixtures | Fixtures cover all legal/illegal discriminators exhaustively | Not justified — example tests sufficient |
| KDF metadata parsing | `dexios-core/tests/key_derivation.rs`, `dexios-domain/tests/keyslots_v1.rs` | Known variants fully enumerated | Not justified — example tests sufficient |
| Archive path normalization | `dexios-domain/tests/pack_paths.rs` (relative paths, traversal) + `dexios-domain/tests/path_identity.rs` | Property test could find novel traversal sequences | Not justified — `pack_paths.rs` and `path_identity.rs` already cover the known traversal cases |
| Detached metadata | `dexios-domain/tests/detached_publication.rs` | Covers partial states by construction | Not justified — state machine is discrete |
| Stream chunking boundaries | `dexios-core/tests/stream_v1.rs` boundary matrix, truncation/duplication tests | Very thorough existing boundary matrix | Not justified — example tests sufficient |

**Verdict:** No targeted proptest additions are justified for Phase 21. All five high-risk
boundaries are adequately covered by existing example tests and fixtures. The archive path
normalization boundary was the only "possibly" candidate; the conclusion is that `pack_paths.rs`
and `path_identity.rs` already cover the known traversal cases without property testing adding
coverage value.

`proptest` 1.9.0 (MSRV 1.84) is noted as the correct tool for future ASR-01 use. No `proptest`
dev-dependency was added in Phase 21. Broad fuzz infrastructure (cargo-fuzz, libfuzzer) is
deferred to ASR-01 per D-17.

## Performance Gate Evidence (RCEV-04)

`scripts/measure_performance_gate.sh` contains realistic throughput thresholds checked by the
existing `performance_notes` gate test in `dexios/tests/verification_gate_docs.rs`. Per D-18,
this gate is maintainer-run evidence only — it is NOT a release-blocking CI step.

The existing `local_scripts_expose_the_full_maintainer_gate` source-gate test asserts that
`measure_performance_gate.sh` is NOT in the default `scripts/verify_phase_gate.sh` path.
This is intentional: performance thresholds reflect the maintainer's hardware and are not
portable release-blocking invariants.

Thresholds are documented in `book/src/technical-details/Performance-Notes.md` as maintainer
evidence, not user or release commitments. The manifest records performance tool availability
via `tool_version` output only; no throughput assertion appears in the release manifest itself.
