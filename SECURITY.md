# Security Policy

## Supported Versions of Dexios

Versions 7 and above will receive security updates, and they will be backported depending on the vulnerability severity.

| Version | Supported          |
| ------- | ------------------ |
| 8.x.x   | ✅                 |
| 7.x.x   | ✅                 |
| 6.x.x   | :x:                |
| 5.0.x   | :x:                |
| 4.0.x   | :x:                |
| < 4.0   | :x:                |

## Supported Versions of Dexios-Core

Currently, all versions of `dexios-core` are supported.

## Reporting a Vulnerability

For an unpatched vulnerability, please use a private GitHub security advisory on the main repository or email `brxken128@tutanota.com`.

Do not open a public issue for an unpatched vulnerability. Public issues are fine for already-patched documentation/source mismatches or non-sensitive hardening follow-ups.

For documentation/source mismatches that affect security-sensitive behavior, please mention whether the issue concerns:

- headers or format compatibility
- KDF selection
- pack/unpack behavior
- detached payload/header partial publication diagnostics and cleanup denial
- delete-after-success cleanup authority, source replacement or changed source tree refusal, or temporary artifact lifecycle behavior
