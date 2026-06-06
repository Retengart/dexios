# Changelog

## Unreleased

### Breaking Changes

- Breaking changes to file format behavior, CLI behavior, security claims, or
  compatibility boundaries must be recorded here before release.
- Removed stale positive verification coverage for removed CLI behavior. Old
  algorithm, erase, and unsupported key-add surfaces are now covered as rejected
  behavior instead of compatibility paths.
- Cleaned up the Rust domain API around unpacking: public unpack construction
  now uses checked `UnpackIntent` state instead of raw request fields, storage
  failure-injection hooks are gated behind the non-default `test-support`
  feature, and typed domain errors preserve safe diagnostic source chains while
  CLI mapping stays class-based and terse.
- Redesigned the canonical V1 archive payload as Dexios-owned manifest-first
  `DXAR` framing with ordered `DXBF` body frames. ZIP bytes and ZIP crate types
  are no longer part of the canonical archive format surface.
- `DEXIOS_KEY` is no longer an implicit fallback key source. Commands must pass
  `--env-key` before Dexios reads `DEXIOS_KEY`; explicit `--keyfile` and `--auto`
  still take precedence.

### Security

- Added a tracked release-note policy for future security-sensitive changes.
- Hardened Phase 11 filesystem transaction and cleanup behavior: linked commit
  evidence now distinguishes complete commit receipts from partial commit
  evidence, cleanup identity is revalidated before ordinary delete-after-success
  cleanup, and delete-after-success remains blocked until complete commit and
  requested hash success.
- Removed the normal full plaintext archive temporary file from pack/unpack
  operation. Pack streams the manifest-first archive payload into V1 encryption;
  unpack validates the manifest before staging selected file bodies and commits
  only after final stream authentication. Plaintext exposure is still present in
  selected staged file bodies and ordinary filesystem temporary/staged files;
  Dexios does not claim secure erase or physical sanitization.
- Migrated the canonical V1 KDF from BLAKE3-Balloon to `Argon2id` (RFC 9106,
  crypto-1) using `argon2 0.5.3` (RustCrypto) with `default-features = false` and
  the `alloc` and `zeroize` features. The canonical Argon2id parameters are
  frozen at m_cost `262_144` KiB (256 MiB), t_cost `4` passes, p_cost `4` lanes,
  output `32` bytes, salt `16` bytes, version `0x13`. The canonical V1 keyslot
  KDF profile ids are unchanged (`0x01` / `0x01`) and now denote Argon2id. The
  `zeroize` feature wipes Argon2's internal memory blocks on drop; this is a
  crate-internal allocation handling claim only.
- Removed the `balloon-hash 0.4.0` dependency. `blake3` is now retained only for
  content hashing (the dexios-domain hasher and cleanup digests); dexios-core no
  longer depends on blake3.
- Rejected explicit invalid generated passphrase counts such as `--auto=0`,
  `--auto=-1`, and non-numeric values before passphrase generation or terminal
  disclosure.
- Resolved the `rand 0.10.0` / `RUSTSEC-2026-0097` exposure by updating to
  `rand 0.10.1` and keeping `cargo audit --deny warnings` in the maintainer
  gate.
- Relaxed the `blake3` constraint from the exact `blake3 = "=1.8.3"` pin to a
  caret range `blake3 = "1.8"` (dep-1). The exact pin existed only while blake3
  was the BLAKE3-Balloon KDF; with the crypto-1 Argon2id migration blake3 left
  the KDF path and is now content-hashing only, so the historical traits-preview
  pin rationale no longer applies and a caret range is acceptable. The resolved
  lock version may remain 1.8.3; only the declared constraint changed.
- Added `deny.toml` cargo-deny policy for advisories, duplicate bans, source
  restrictions, and license allowlisting.
- Hardened release publication so provenance and SBOM attestations are created
  before GitHub Release assets are uploaded.
- Hardened in-place header/key mutation reads to use the no-follow resolved
  target path instead of a plain path read after identity capture.

### Verification

- Added source gates for spec freshness and release workflow ordering so stale
  format claims block the maintainer gate.
- Added the Phase 7 maintainer verification gate policy as tracked project
  documentation.
- Added Phase 11 source gates for linked commit evidence, changed cleanup identity
  revalidation, delete-after-success proof, and honest filesystem limitations:
  committed outputs are not rolled back after cleanup failure, and Dexios makes
  no secure erase, no physical sanitization, and no full power-failure proof
  claims.
- Made `scripts/verify_phase_gate.sh` the authoritative maintainer gate:
  formatting, clippy, workspace release tests, `cargo audit --deny warnings`,
  `cargo deny check`, release-lto CLI smoke, mdBook rebuild, generated-docs
  freshness, repo hygiene, and whitespace diff checks.
- Repaired CLI smoke and black-box CI coverage so removed `--aes`, `--argon`,
  `--zstd`, `--erase`, top-level `erase`, and `key add -n` behavior is rejected
  rather than positively invoked.
- Added focused KDF measurement evidence with hardware-profile logging and
  opt-in `--max-kdf-seconds` / `DEXIOS_KDF_MAX_SECONDS` threshold enforcement.
- Added focused performance thresholds for stream encryption, stream
  decryption, pack, unpack, and temp-space measurements, with per-run work
  directories under `target/phase7-measurements/`.
- Added capacity-pressure reporting for pack and unpack when preserved IO
  sources expose storage pressure such as full storage, quota, or file-size
  limits.
- Added `scripts/generate_release_manifest.sh` to record release candidate
  commit/tag evidence, tracked dirty state, `Cargo.lock` SHA256, Cargo metadata
  evidence, tool versions, the verification command contract, and asset SHA256
  hashes.
- Removed generated mdBook HTML from the tracked release evidence. The
  maintainer gate now verifies documentation freshness with
  `mdbook build --dest-dir target/mdbook` while keeping `book/src/` as the
  committed documentation source.

### Documentation

- Corrected the whitepaper-style V1 format reference to the current 512-byte
  canonical header, Argon2id KDF policy, and DXAR/DXBF manifest-first
  archive framing.
- Documented Phase 11 filesystem transaction and cleanup limits in the safety
  contract and mdBook technical notes, including ordinary delete-after-success
  cleanup, partial commit evidence, committed outputs are not rolled back, and
  no secure erase or physical sanitization claims.
- Documented Phase 12 performance thresholds and capacity-pressure reporting.
- Documented the current manifest-first archive payload behavior and source-gated
  that no full plaintext archive temporary file is created during normal
  pack/unpack operation.
- Added Phase 20 Docs, Spec, and Generated Artifact Fidelity release-facing
  wording for canonical V1 fact reconciliation, PDF/generated artifact policy,
  source gates, ordinary delete-after-success cleanup, no secure erase, no
  physical sanitization, and no recovery overclaims.
- Documented the release manifest workflow and its non-claims: no bit-for-bit
  reproducibility, signing trust, SBOM completeness, SBOM protection,
  supply-chain prevention, completed verification, or runtime safety beyond
  separately completed gate results.
- Documented release asset-name content truth: the current release workflow
  builds `dexios-${GITHUB_REF_NAME}-linux-amd64`,
  `dexios-${GITHUB_REF_NAME}-macos-amd64`, and
  `dexios-${GITHUB_REF_NAME}-windows-amd64.exe` basenames, while the release
  manifest records only supplied asset basenames and SHA256 values. The manifest
  does not claim a complete platform asset set before Phase 21 enforcement.
- Documented the Phase 9 KDF feature policy, generated passphrase validation,
  focused KDF measurement workflow, and narrow secret-memory claim boundaries.
- Documented the release-note trigger and local-only `local-notes/` boundary for
  future maintainers.
- Updated maintainer documentation to describe the dependency, cargo-deny, CLI,
  generated-docs, and hygiene gates without requiring local planning artifacts.
