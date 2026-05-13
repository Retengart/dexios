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
  failure-injection hooks are gated out of the default production API, and typed
  domain errors preserve safe diagnostic source chains while CLI mapping stays
  class-based and terse.

### Security

- Added a tracked release-note policy for future security-sensitive changes.
- Enabled the `balloon-hash 0.4.0` `zeroize` feature and source-gated the
  BLAKE3-Balloon dependency policy while keeping `blake3 = "=1.8.3"` pinned.
- Rejected explicit invalid generated passphrase counts such as `--auto=0`,
  `--auto=-1`, and non-numeric values before passphrase generation or terminal
  disclosure.
- Resolved the `rand 0.10.0` / `RUSTSEC-2026-0097` exposure by updating to
  `rand 0.10.1` and keeping `cargo audit --deny warnings` in the maintainer
  gate.
- Kept `blake3 = "=1.8.3"` because `1.8.4` and newer move the traits-preview
  digest line in a way that breaks the current stable `balloon-hash 0.4.0` KDF
  integration.
- Added `deny.toml` cargo-deny policy for advisories, duplicate bans, source
  restrictions, and license allowlisting.

### Verification

- Added the Phase 7 maintainer verification gate policy as tracked project
  documentation.
- Made `scripts/verify_phase_gate.sh` the authoritative maintainer gate:
  formatting, clippy, workspace release tests, `cargo audit --deny warnings`,
  `cargo deny check`, release-lto CLI smoke, mdBook rebuild, generated-docs
  freshness, repo hygiene, and whitespace diff checks.
- Repaired CLI smoke and black-box CI coverage so removed `--aes`, `--argon`,
  `--zstd`, `--erase`, top-level `erase`, and `key add -n` behavior is rejected
  rather than positively invoked.
- Added focused KDF measurement evidence with hardware-profile logging and
  opt-in `--max-kdf-seconds` / `DEXIOS_KDF_MAX_SECONDS` threshold enforcement.

### Documentation

- Documented the Phase 9 KDF feature policy, generated passphrase validation,
  focused KDF measurement workflow, and narrow secret-memory claim boundaries.
- Documented the release-note trigger and local-only `local-notes/` boundary for
  future maintainers.
- Updated maintainer documentation to describe the dependency, cargo-deny, CLI,
  generated-docs, and hygiene gates without requiring local planning artifacts.
