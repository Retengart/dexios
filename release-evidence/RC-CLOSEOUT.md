# Dexios v3.0 Release Candidate Closeout Evidence

This document names the verification contracts and evidence for the v3.0 release candidate.
It records command names and structural evidence and does not claim proof of completion;
use a completed gate log or current `bash scripts/verify_phase_gate.sh` run for pass/fail
evidence. Each section records what was checked and under what conditions; no assertion is
made that every condition holds on every platform or in every build environment.

## Blocker-to-Check Traceability Matrix

TBD — filled in 21-05 after all blocker-closing evidence is committed.

Placeholder blocker ID prefixes covered by this document:
PATH-, DASI-, DETP-, HDRM-, APIF-, DOCS-, CIGR-, RCEV-

| Blocker ID | Failure Class | Regression Test(s) | Docs/Source Gate(s) | CI/Release Check(s) |
|------------|--------------|-------------------|--------------------|--------------------|
| PATH-01..04 | TBD — filled in 21-05 | TBD | TBD | TBD |
| DASI-01..04 | TBD — filled in 21-05 | TBD | TBD | TBD |
| DETP-01..04 | TBD — filled in 21-05 | TBD | TBD | TBD |
| HDRM-01..04 | TBD — filled in 21-05 | TBD | TBD | TBD |
| APIF-01..04 | TBD — filled in 21-05 | TBD | TBD | TBD |
| DOCS-01..04 | TBD — filled in 21-05 | TBD | TBD | TBD |
| CIGR-01..05 | TBD — filled in 21-05 | TBD | TBD | TBD |
| RCEV-01..05 | TBD — filled in 21-05 | TBD | TBD | TBD |

## Accepted Residual Risks

- **ordinary (non-secure-erase) deletion:** Cleanup uses `std::fs::remove_*`, which performs
  ordinary filesystem deletion rather than physical media sanitization. Files removed by
  delete-after-success are unlinked from the directory tree; overwrite behaviour depends on
  the filesystem and OS. No claim is made that this erases data from physical storage.

- **Unpack plaintext temporary exposure:** The V1 unpack architecture requires a seekable
  plaintext temporary ZIP before entry extraction. This exposure is documented in
  `book/src/technical-details/Secure-Erase.md` and bounded by ordinary temp-file cleanup.
  It is not eliminated.

- **Detached partial publication:** Detached-header mode reports errors with evidence when
  partial publication occurs; it does not perform recovery or rollback of already-committed
  artifacts. The failure class is error-with-evidence, not silent data loss.

- **Windows filesystem identity:** Windows filesystem identity uses `GetFileInformationByHandle`
  (volume serial + file index) rather than POSIX `(dev, ino)` pairs. Symlink rejection
  uses `std::os::windows::fs` file attribute checks rather than `lstat`. These are weaker
  than Unix. Build-only Windows support is named explicitly here, not implied by
  cross-platform identity claims.

## Platform Limits

- **Symlink rejection tests:** Symlink rejection tests use Unix-only POSIX `lstat` semantics.
  The `#[cfg(unix)]` arms in `dexios-domain/tests/path_identity.rs`,
  `dexios-domain/tests/cleanup_receipts.rs`, `dexios-domain/tests/header_restore.rs`,
  and `dexios-domain/tests/keyslots_v1.rs` are excluded on Windows — this is the honest
  behaviour, not a test gap.

- **Same-inode identity:** Unix same-inode identity uses the `(dev, ino)` pair from
  POSIX `stat`. Windows identity uses volume serial number + file index via
  `GetFileInformationByHandle`, which covers the common case but has documented edge cases
  around hardlinks and certain virtual filesystems.

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
  advisory scanning is deferred to future milestone scope.

- **Secure erase or physical media sanitization:** Dexios deletion uses ordinary filesystem
  `unlink` operations. No overwrite pass, secure-delete primitive, or physical sanitization
  is performed or claimed.

- **V2 format redesign:** A V2 file format is deferred to FMT-01 and is out of scope for
  v3.0. The current V1 format is the only supported format.

- **Broad fuzz/property infrastructure (deferred to ASR-01):** Broad fuzz corpus maintenance,
  libfuzzer integration, and property-testing infrastructure across all parsers are deferred
  to ASR-01. Phase 21 adds only targeted property tests where a high-risk boundary is better
  proved by property testing than by existing example tests.

- **Signed artifact attestations (deferred to ASR-02):** Signed release artifacts, SLSA
  provenance attestations, and keyless signing via Sigstore are deferred to ASR-02 and are
  out of scope for v3.0.

## Property and Fuzz Coverage Decision (RCEV-03)

TBD — filled in 21-05.

## Performance Gate Evidence (RCEV-04)

TBD — filled in 21-05.
