#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'USAGE'
Usage: scripts/generate_release_manifest.sh --output <path> [options]

Options:
  --output <path>   Write the release manifest to this path.
  --asset <path>    Add an asset file and record its SHA256. May be repeated.
  --tag <tag>       Require this git tag to point at the current commit.
  --allow-dirty     Allow tracked working tree changes for local dry runs.
  --help            Show this help.

Without --allow-dirty, tracked working tree changes fail closed. Untracked files
are ignored by the dirty check.

The verification command section records the required command contract. It is
not a pass/fail log for those commands.
USAGE
}

output=""
tag=""
allow_dirty=0
assets=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            [[ $# -ge 2 ]] || {
                echo "--output requires a path" >&2
                exit 2
            }
            output=$2
            shift 2
            ;;
        --asset)
            [[ $# -ge 2 ]] || {
                echo "--asset requires a path" >&2
                exit 2
            }
            assets+=("$2")
            shift 2
            ;;
        --tag)
            [[ $# -ge 2 ]] || {
                echo "--tag requires a tag name" >&2
                exit 2
            }
            tag=$2
            shift 2
            ;;
        --allow-dirty)
            allow_dirty=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ -n "$output" ]] || {
    echo "--output is required" >&2
    usage >&2
    exit 2
}

sha256_file() {
    local path=$1

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        echo "sha256sum or shasum is required" >&2
        exit 2
    fi
}

tool_version() {
    local label=$1
    shift
    local stdout_file
    local stderr_file

    stdout_file="$(mktemp "${TMPDIR:-/tmp}/dexios-release-tool-version.XXXXXX")"
    stderr_file="$(mktemp "${TMPDIR:-/tmp}/dexios-release-tool-version-err.XXXXXX")"

    if "$@" >"$stdout_file" 2>"$stderr_file"; then
        local version
        version="$(tr '\n' ' ' <"$stdout_file" | sed 's/[[:space:]]*$//')"
        rm -f "$stdout_file" "$stderr_file"
        printf '%s' "$version"
    else
        rm -f "$stdout_file" "$stderr_file"
        printf '%s unavailable' "$label"
    fi
}

target_platform() {
    local rustc_verbose
    if ! rustc_verbose="$(rustc -vV 2>/dev/null)"; then
        printf 'rustc -vV unavailable'
        return
    fi

    local host
    host="$(printf '%s\n' "$rustc_verbose" | awk -F': ' '/^host: / { print $2; exit }')"
    if [[ -n "$host" ]]; then
        printf '%s' "$host"
    else
        printf 'unknown'
    fi
}

tracked_dirty=clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    tracked_dirty=dirty
fi

if [[ "$allow_dirty" -eq 0 && "$tracked_dirty" != clean ]]; then
    echo "Tracked working tree changes are present. Use --allow-dirty only for local dry runs." >&2
    exit 1
fi

commit="$(git rev-parse HEAD)"
short_commit="$(git rev-parse --short HEAD)"

if [[ -n "$tag" ]]; then
    tag_ref="refs/tags/$tag"
    if ! git show-ref --verify --quiet "$tag_ref"; then
        echo "Tag not found: $tag" >&2
        exit 1
    fi
    tag_commit="$(git rev-parse -q --verify "${tag_ref}^{commit}")" || {
        echo "Tag does not resolve to a commit: $tag" >&2
        exit 1
    }
    if [[ "$tag_commit" != "$commit" ]]; then
        echo "Tag $tag does not point at the current commit $commit" >&2
        exit 1
    fi
    release_tag="$tag"
else
    release_tag="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
    [[ -n "$release_tag" ]] || release_tag="untagged"
fi

for asset in "${assets[@]}"; do
    [[ -f "$asset" ]] || {
        echo "Asset does not exist or is not a file: $asset" >&2
        exit 1
    }
done

[[ -f Cargo.lock ]] || {
    echo "Cargo.lock is missing" >&2
    exit 1
}

metadata_file="$(mktemp "${TMPDIR:-/tmp}/dexios-cargo-metadata.XXXXXX")"
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --format-version=1 --locked >"$metadata_file"
metadata_sha="$(sha256_file "$metadata_file")"
target_platform_value="$(target_platform)"

mkdir -p "$(dirname "$output")"

{
    printf '# Dexios Release Manifest\n\n'
    printf '## Revision\n\n'
    printf -- '- commit: `%s`\n' "$commit"
    printf -- '- short commit: `%s`\n' "$short_commit"
    printf -- '- tag: `%s`\n' "$release_tag"
    printf -- '- tracked dirty state: `%s`\n' "$tracked_dirty"
    printf -- '- allow dirty: `%s`\n\n' "$allow_dirty"

    printf '## Workspace Evidence\n\n'
    printf -- '- `Cargo.lock` SHA256: `%s`\n' "$(sha256_file Cargo.lock)"
    printf -- '- Cargo metadata command: `cargo metadata --format-version=1 --locked`\n'
    printf -- '- Cargo metadata SHA256: `%s`\n\n' "$metadata_sha"

    printf '## Target Platforms\n\n'
    printf -- '- target platform: `%s`\n' "$target_platform_value"
    printf -- '- target platform command: `rustc -vV`\n\n'

    printf '## Tool Versions\n\n'
    printf -- '- `rustc --version`: `%s`\n' "$(tool_version rustc rustc --version)"
    printf -- '- `cargo --version`: `%s`\n' "$(tool_version cargo cargo --version)"
    printf -- '- `cargo audit --version`: `%s`\n' "$(tool_version cargo-audit cargo audit --version)"
    printf -- '- `cargo deny --version`: `%s`\n' "$(tool_version cargo-deny cargo deny --version)"
    printf -- '- `mdbook --version`: `%s`\n' "$(tool_version mdbook mdbook --version)"
    printf -- '- `typst --version`: `%s`\n\n' "$(tool_version typst typst --version)"

    printf '## Verification Command Contract\n\n'
    printf 'These commands are the required verification contract for this release candidate. This section records command names and does not prove that the commands completed successfully; use a completed gate log or current `bash scripts/verify_phase_gate.sh` run for pass/fail evidence.\n\n'
    printf -- '- `cargo fmt --all --check`\n'
    printf -- '- `cargo clippy --workspace --all-targets --all-features --no-deps`\n'
    printf -- '- `cargo test --workspace --all-features --release --verbose`\n'
    printf -- '- `bash scripts/verify_assurance_replay.sh`\n'
    printf -- '- `cargo audit --deny warnings`\n'
    printf -- '- `cargo deny check`\n'
    printf -- '- `cargo build -p dexios --profile release-lto`\n'
    printf -- '- `bash scripts/verify_cli_surface.sh`\n'
    printf -- '- `bash scripts/generate_release_manifest.sh --output %q' "$output"
    for asset in "${assets[@]}"; do
        printf ' --asset %q' "$asset"
    done
    [[ -z "$tag" ]] || printf ' --tag %q' "$tag"
    [[ "$allow_dirty" -eq 0 ]] || printf ' --allow-dirty'
    printf '`\n'
    printf -- '- `mdbook build`\n'
    printf -- '- `git diff --exit-code -- docs`\n'
    printf -- '- `typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf`\n'
    printf -- '- `git diff --exit-code -- spec/dexios-paper.pdf`\n'
    printf -- '- `bash scripts/verify_repo_hygiene.sh`\n'
    printf -- '- `git diff --check`\n'
    printf -- '- `bash scripts/verify_phase_gate.sh`\n\n'

    printf '## Assets\n\n'
    printf 'Asset entries record only files passed with `--asset` by basename and SHA256. This manifest does not claim a complete platform asset set; Phase 21 owns full expected asset-set enforcement and publishing gates.\n\n'
    if [[ "${#assets[@]}" -eq 0 ]]; then
        printf 'No release assets were recorded.\n\n'
    else
        local_asset_index=0
        for asset in "${assets[@]}"; do
            local_asset_index=$((local_asset_index + 1))
            printf '### Asset %d\n\n' "$local_asset_index"
            printf -- '- path: `%s`\n' "$asset"
            printf -- '- name: `%s`\n' "$(basename "$asset")"
            printf -- '- SHA256: `%s`\n\n' "$(sha256_file "$asset")"
        done
    fi

    printf '## Claim Limits\n\n'
    printf 'This manifest records local evidence for one release candidate. It does not claim bit-for-bit reproducibility, signing trust, SBOM completeness, SBOM protection, supply-chain prevention, completed verification, or runtime safety beyond separately completed gate results for this candidate.\n'
} >"$output"

printf 'Release manifest written to %s\n' "$output"
