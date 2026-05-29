## Auditing

Dexios does not currently document a full-project external audit for the current workspace.

The practical audit surface for Dexios lives in:

- `dexios-core/src/header.rs`
- `dexios-core/src/key.rs`
- `dexios-core/src/stream.rs`
- `dexios-core/src/cipher.rs`
- `dexios-core/src/primitives.rs`
- `dexios-core/src/protected.rs`

If you are auditing end-to-end file workflows rather than only the primitives, also review:

- `dexios-domain/src/encrypt.rs`
- `dexios-domain/src/decrypt.rs`
- `dexios-domain/src/pack.rs`
- `dexios-domain/src/unpack.rs`
- `dexios-domain/src/storage.rs`

The repository currently relies heavily on Rust's type system, explicit error handling, compatibility tests, and CI checks, but that is not a substitute for a dedicated independent audit.

The Maintainer Verification Gate in `book/src/Safety-Contract.md` is the practical
pre-merge gate for safety-sensitive changes. It requires focused invariant
checks, broad workspace checks, dependency/security checks, and documentation
checks, but it is still not a substitute for a dedicated independent audit.

## Dependency currency

Dexios aims to keep dependencies current, but the dependency graph deliberately
tolerates a small set of duplicate (older) crate versions. These are documented
inline in `deny.toml`'s `[bans] skip` list and enforced by `cargo deny check`
(`multiple-versions = "deny"`), so the set cannot grow silently.

The duplicates have two distinct causes:

- **Trailing RustCrypto 0.10 / `aead 0.5` line (most entries).** The AEAD and KDF
  cipher stack (`chacha20poly1305 0.10.1`, `aead 0.5.2`, `argon2 0.5.3`,
  `cipher 0.4.4`, `crypto-common 0.1.7`, `password-hash 0.5.0`) still depends on
  the older RustCrypto 0.10-era crates, which pull in older versions of
  `chacha20`, `cpufeatures`, `rand_core`, and `getrandom`. Our RNG dependency
  `rand 0.10.1` has already moved onto the newer line, so both coexist. The plan
  is to collapse onto the `aead 0.6` / `chacha20poly1305 0.11` stack once it is
  available across the cipher graph; that upgrade carries the newer transitive
  dependencies and the duplicates disappear, at which point the matching `skip`
  entries are removed.
- **`rpassword`/`rtoolbox` Windows prompt dependency (one entry).** The
  `windows-sys 0.59` skip is unrelated to the cipher stack: it exists only
  because `rpassword`/`rtoolbox` lag behind the rest of the Windows transitive
  graph (which is on `windows-sys 0.61`). It is removed once those crates catch
  up.

Each `skip` entry was verified against the current `Cargo.lock` with
`cargo tree -i <crate>` and should be re-checked (and dropped if no longer
duplicated) whenever the cipher stack or prompt dependency is bumped.

How the project keeps dependencies current:

- **`cargo deny check`** gates licenses, sources, advisories, and the
  duplicate-version policy above on every run of the Maintainer Verification
  Gate.
- **`cargo audit --deny warnings`** fails the gate on any known advisory
  (RUSTSEC) affecting the locked graph.
- **Dependabot** runs weekly with grouped pull requests (see
  `.github/dependabot.yml`): a `cargo-version` group for routine version
  updates and a `cargo-security` group scoped to security updates.

> **Operator action required:** the `cargo-security` Dependabot group only
> produces security-update pull requests when **GitHub Dependabot alerts are
> enabled** for the repository. Without alerts enabled, security updates will
> not be surfaced. Enable Dependabot alerts in the repository security settings
> so the `cargo-security` group can do its job.
