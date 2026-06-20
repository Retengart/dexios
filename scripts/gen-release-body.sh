#!/usr/bin/env bash
# Generate the GitHub release body for a dexios release.
#
#   gen-release-body.sh <version> [changelog] [output]
#
# The body is fully deterministic from <version> and the changelog, so the
# publish job can safely set it as the release body regardless of which
# workflow step creates it.
#
#   - Downloads table: links to release assets by platform.
#   - "What's new": the "## vX.Y.Z" section of the changelog.
#   - Verification: how to check the keyless cosign bundle + build provenance.
set -euo pipefail

VERSION="${1:?usage: gen-release-body.sh <version> [changelog] [output]}"
CHANGELOG="${2:-CHANGELOG.md}"
OUTPUT="${3:--}"

REPO="brxken128/dexios"
BASE="https://github.com/$REPO/releases/download/v$VERSION"

# --- "What's new": extract the section for this version -----------------------
whatsnew="$(
  tr -d '\r' < "$CHANGELOG" \
  | awk -v hdr="## v$VERSION" '
      $0 == hdr || index($0, hdr " ") == 1 { grab = 1; next }
      grab && /^## / { exit }
      grab && /^### / { print; next }
      grab { print }
    ' \
  | sed -e 's/^[[:space:]]*//'
)"
if [ -z "$whatsnew" ]; then
  # Fallback: try without "v" prefix
  whatsnew="$(
    tr -d '\r' < "$CHANGELOG" \
    | awk -v hdr="## $VERSION" '
        $0 == hdr || index($0, hdr " ") == 1 { grab = 1; next }
        grab && /^## / { exit }
        grab && /^### / { print; next }
        grab { print }
      ' \
    | sed -e 's/^[[:space:]]*//'
  )"
fi

# --- Assemble the body --------------------------------------------------------
body="$(cat <<EOF
## Downloads

| Platform | Binary | SBOM | Cosign bundle |
|---|---|---|---|
| **Linux** (x86-64) | [dexios]($BASE/dexios-v${VERSION}-linux-amd64) | [cdx.json]($BASE/dexios-v${VERSION}-linux-amd64.cdx.json) | [sigstore.json]($BASE/dexios-v${VERSION}-linux-amd64.sigstore.json) |
| **macOS** (x86-64) | [dexios]($BASE/dexios-v${VERSION}-macos-amd64) | [cdx.json]($BASE/dexios-v${VERSION}-macos-amd64.cdx.json) | [sigstore.json]($BASE/dexios-v${VERSION}-macos-amd64.sigstore.json) |
| **Windows** (x86-64) | [dexios.exe]($BASE/dexios-v${VERSION}-windows-amd64.exe) | [cdx.json]($BASE/dexios-v${VERSION}-windows-amd64.exe.cdx.json) | [sigstore.json]($BASE/dexios-v${VERSION}-windows-amd64.exe.sigstore.json) |

Install from source: \`cargo install dexios --locked --version $VERSION\`

---

$([ -n "$whatsnew" ] && printf '## What'\''s new in v%s\n\n%s\n\n---\n\n' "$VERSION" "$whatsnew" || printf '')

## Verifying your download

Every artifact is signed with keyless [cosign](https://github.com/sigstore/cosign) (a \`<file>.sigstore.json\` bundle ships next to it) and carries a GitHub build-provenance attestation. No keys to trust — the signature is bound to the exact GitHub Actions run that built the file.

Build provenance (easiest, needs the [\`gh\`](https://cli.github.com/) CLI):

\`\`\`sh
gh attestation verify <file> --repo $REPO
\`\`\`

Cosign bundle (download the matching \`<file>.sigstore.json\` too):

\`\`\`sh
cosign verify-blob <file> \\
  --bundle <file>.sigstore.json \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  --certificate-identity-regexp '^https://github.com/$REPO/\.github/workflows/'
\`\`\`

See [SIGNING.md](https://github.com/$REPO/blob/main/SIGNING.md) for full verification details.
EOF
)"

if [ "$OUTPUT" = "-" ]; then
  printf '%s\n' "$body"
else
  printf '%s\n' "$body" > "$OUTPUT"
fi
