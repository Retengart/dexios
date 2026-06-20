# Verifying Dexios Releases

Every release artifact is signed in CI with **keyless Sigstore** (GitHub Actions
OIDC + Fulcio + the Rekor transparency log) — no maintainer key, nothing to leak.
Each artifact ships with a `<artifact>.sigstore.json` bundle, and a
build-provenance attestation is published to GitHub.

Install [cosign](https://docs.sigstore.dev/cosign/installation/) and the
[GitHub CLI](https://cli.github.com/).

## 1. Authenticity (cosign) — strict, pins the producing workflow

```bash
cosign verify-blob <artifact> \
  --bundle <artifact>.sigstore.json \
  --certificate-identity 'https://github.com/brxken128/dexios/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## 2. Provenance (GitHub CLI) — strict

```bash
gh attestation verify <artifact> \
  --repo brxken128/dexios \
  --signer-workflow brxken128/dexios/.github/workflows/release.yml
```

## Artifact naming

All release artifacts follow the pattern `dexios-vX.Y.Z-<platform>`. Each has:

| Suffix | Description |
|---|---|
| (none) | Binary |
| `.cdx.json` | CycloneDX 1.5 SBOM |
| `.sigstore.json` | Sigstore cosign bundle (keyless signature + Rekor proof) |

A looser "is this any official dexios artifact" check replaces
`--certificate-identity` with
`--certificate-identity-regexp '^https://github.com/brxken128/dexios/\.github/workflows/.+@refs/heads/main$'`.

The `.sigstore.json` bundle embeds the Rekor inclusion proof, so
`cosign verify-blob` can run fully offline given a `--trusted-root`.
