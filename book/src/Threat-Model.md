# Threat Model and Memory-Residency Scope

Dexios protects file confidentiality and integrity against an attacker who obtains the
ciphertext and header. This page records what is intentionally **out of scope** for
in-process secret handling, so the boundaries are explicit rather than implied. These are
conscious decisions, not oversights.

## In scope

- Authenticated encryption of payloads (XChaCha20-Poly1305 over the LE31 stream).
- Tamper / downgrade / truncation detection via header-bound AAD and per-keyslot AAD.
- Memory-hard password hashing (Argon2id, 256 MiB / t=4 / p=4) before keyslot unwrap.
- Zeroize-on-drop of key material, derived keys, passwords, and decrypted scratch buffers
  via `Protected<T>` and `Zeroizing`.

## Out of scope (conscious decisions)

- **Memory locking (mlock / VirtualLock).** The workspace lint and every Dexios
  crate root use `forbid(unsafe_code)`.
  Locking pages requires `unsafe` FFI (directly or via a crate), which we deliberately do
  not introduce into the cryptographic core. Consequently, live secrets may be paged to
  swap or captured in a hibernation image or core dump, where `zeroize` cannot reach them.
- **Allocator / OS / terminal / crash-dump sanitization.** `zeroize` clears the buffers we
  own; it cannot clear copies made by the allocator, the kernel, the terminal scrollback,
  or third-party AEAD internals.
- **Environment-variable key input.** Dexios does not accept key material from
  environment variables. Environment-based secrets can be captured by shells,
  process launchers, CI logs, crash reports, and host inspection tooling before
  an application can scrub them. Use an interactive prompt, a keyfile, or
  `--keyfile -` on standard input for automation.

## Output file permissions

On Unix, **all** committed outputs — encrypted artifacts, detached headers, and **decrypted
plaintext / unpacked files** — are published with owner-only `0o600` permissions rather than
the umask default. This is a deliberate defense-in-depth choice: a freshly decrypted secret
should not be world- or group-readable by default, even though that is stricter than typical
`create` semantics. Loosen the permissions explicitly (e.g. `chmod`) if wider access is
intended.

## Recommended operator mitigations

- Encrypt your swap device, or use a swapless / encrypted-hibernation configuration.
- Disable core dumps for sensitive runs (`ulimit -c 0`).
- Prefer interactive prompts or keyfiles on shared or multi-user hosts.
