## Supported Versions

Dexios currently provides security support for:

| Version | Supported |
| ------- | --------- |
| 8.x.x   | Yes       |
| 7.x.x   | Yes       |
| 6.x.x   | No        |
| 5.0.x   | No        |
| 4.0.x   | No        |
| < 4.0   | No        |

All published `dexios-core` versions are currently listed as supported in the repository security policy.

## Reporting a Vulnerability

For an unpatched vulnerability, use a private GitHub security advisory on the main repository or email:

```text
brxken128@tutanota.com
```

Do not open a public issue for an unpatched vulnerability. Public issues are fine for already-patched documentation/source mismatches or non-sensitive hardening follow-ups.

Useful reports include:

- affected version
- reproduction steps
- whether the issue affects confidentiality, integrity, or availability
- whether it is format-compatibility-sensitive
- whether it concerns headers or format compatibility
- whether it concerns KDF selection
- whether it concerns pack/unpack behavior
- whether it concerns detached payload/header partial publication diagnostics and cleanup denial
- whether it concerns delete-after-success cleanup authority
- whether it concerns source replacement or changed source tree refusal
- whether it concerns temporary artifact lifecycle behavior
