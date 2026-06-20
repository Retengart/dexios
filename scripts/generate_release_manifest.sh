#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

EXPECTED_CARGO_AUDIT_VERSION=0.22.1
EXPECTED_CARGO_DENY_VERSION=0.19.6

usage() {
    cat <<'USAGE'
Usage: scripts/generate_release_manifest.sh --output <path> [options]

Options:
  --output <path>   Write the release manifest to this path.
  --asset <path>    Add an asset file and record its SHA256. May be repeated.
  --tag <tag>       Require this git tag to point at the current commit.
  --allow-dirty     Allow tracked working tree changes for local dry runs.
  --help            Show this help.

Without --allow-dirty, tracked working tree changes and release-sensitive
untracked files fail closed. Use --allow-dirty only for local dry runs; dry-run
manifests are not release-equivalent.

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

tool_version_matches() {
    local observed=$1
    local expected=$2
    local observed_version

    observed_version="$(observed_tool_version_token "$observed")"
    [[ "$observed_version" == "$expected" ]]
}

observed_tool_version_token() {
    local observed=$1
    local word

    for word in $observed; do
        if [[ "$word" =~ ^v?([0-9]+[.][0-9]+[.][0-9]+([-+.][0-9A-Za-z][0-9A-Za-z.+-]*)?)$ ]]; then
            printf '%s' "${BASH_REMATCH[1]}"
            return
        fi
    done
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

is_release_sensitive_untracked_path() {
    local path=$1

    case "$path" in
        target/* | \
        local-notes/* | \
        local-plans/* | \
        .local-tools/*)
            return 1
            ;;
    esac

    case "$path" in
        .gitattributes | \
        .github/workflows/* | \
        book/src/* | \
        scripts/* | \
        spec/* | \
        release-evidence/* | \
        dexios*/src/* | \
        dexios*/tests/* | \
        Cargo.toml | \
        Cargo.lock | \
        deny.toml | \
        book.toml | \
        CHANGELOG.md | \
        CONTRIBUTING.md | \
        README.md | \
        SECURITY.md | \
        default.nix | \
        flake.nix | \
        shell.nix | \
        *.rs | \
        *.toml | \
        *.lock | \
        *.md | \
        *.yml | \
        *.yaml | \
        *.sh | \
        *.typ | \
        *.pdf)
            return 0
            ;;
    esac

    return 1
}

collect_release_sensitive_untracked_paths() {
    local line
    local path

    while IFS= read -r line; do
        [[ "$line" == '?? '* ]] || continue
        path=${line#'?? '}

        if is_release_sensitive_untracked_path "$path"; then
            printf '%s\n' "$path"
        fi
    done < <(git status --porcelain --untracked-files=all)
}

tracked_dirty=clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    tracked_dirty=dirty
fi

mapfile -t release_sensitive_untracked_paths < <(collect_release_sensitive_untracked_paths)
release_sensitive_untracked_state=clean
if [[ "${#release_sensitive_untracked_paths[@]}" -gt 0 ]]; then
    release_sensitive_untracked_state=dirty
fi

local_dry_run=no
release_equivalent=yes
if [[ "$allow_dirty" -ne 0 ]]; then
    local_dry_run=yes
    release_equivalent=no
fi
if [[ "$tracked_dirty" != clean || "$release_sensitive_untracked_state" != clean ]]; then
    release_equivalent=no
fi

if [[ "$allow_dirty" -eq 0 && "$tracked_dirty" != clean ]]; then
    echo "Tracked working tree changes are present. Use --allow-dirty only for local dry runs." >&2
    exit 1
fi

if [[ "$allow_dirty" -eq 0 && "$release_sensitive_untracked_state" != clean ]]; then
    echo "Release-sensitive untracked files are present; track or remove them before release-equivalent evidence:" >&2
    printf '  - %s\n' "${release_sensitive_untracked_paths[@]}" >&2
    exit 1
fi

if [[ "$allow_dirty" -eq 0 ]]; then
    bash scripts/verify_repo_hygiene.sh >/dev/null
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

rustc_version="$(tool_version rustc rustc --version)"
cargo_version="$(tool_version cargo cargo --version)"
cargo_audit_version="$(tool_version cargo-audit cargo audit --version)"
cargo_deny_version="$(tool_version cargo-deny cargo deny --version)"

release_tool_equivalence_state=clean
tool_mismatch_messages=()
if ! tool_version_matches "$cargo_audit_version" "$EXPECTED_CARGO_AUDIT_VERSION"; then
    tool_mismatch_messages+=("cargo-audit expected $EXPECTED_CARGO_AUDIT_VERSION, observed $cargo_audit_version")
fi
if ! tool_version_matches "$cargo_deny_version" "$EXPECTED_CARGO_DENY_VERSION"; then
    tool_mismatch_messages+=("cargo-deny expected $EXPECTED_CARGO_DENY_VERSION, observed $cargo_deny_version")
fi

if [[ "${#tool_mismatch_messages[@]}" -gt 0 ]]; then
    release_tool_equivalence_state=dirty
    release_equivalent=no
fi

if [[ "$allow_dirty" -eq 0 && "$release_tool_equivalence_state" != clean ]]; then
    echo "Release-equivalent tool version mismatch:" >&2
    printf '  - %s\n' "${tool_mismatch_messages[@]}" >&2
    exit 1
fi

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
    printf -- '- release-sensitive untracked state: `%s`\n' "$release_sensitive_untracked_state"
    if [[ "${#release_sensitive_untracked_paths[@]}" -eq 0 ]]; then
        printf -- '- release-sensitive untracked paths: `none`\n'
    else
        printf -- '- release-sensitive untracked paths:\n'
        for path in "${release_sensitive_untracked_paths[@]}"; do
            printf '  - `%s`\n' "$path"
        done
    fi
    printf -- '- allow dirty: `%s`\n' "$allow_dirty"
    printf -- '- local dry run: `%s`\n' "$local_dry_run"
    printf -- '- release-equivalent: `%s`\n\n' "$release_equivalent"
    if [[ "$local_dry_run" == yes ]]; then
        printf 'This manifest is a local dry run and is not release-equivalent.\n\n'
    fi

    printf '## Workspace Evidence\n\n'
    printf -- '- `Cargo.lock` SHA256: `%s`\n' "$(sha256_file Cargo.lock)"
    printf -- '- Cargo metadata command: `cargo metadata --format-version=1 --locked`\n'
    printf -- '- Cargo metadata SHA256: `%s`\n\n' "$metadata_sha"

    printf '## Target Platforms\n\n'
    printf -- '- target platform: `%s`\n' "$target_platform_value"
    printf -- '- target platform command: `rustc -vV`\n\n'

    printf '## Tool Versions\n\n'
    printf -- '- release-equivalent tool versions: `%s`\n' "$release_tool_equivalence_state"
    printf -- '- expected `cargo-audit`: `%s`\n' "$EXPECTED_CARGO_AUDIT_VERSION"
    printf -- '- observed `cargo audit --version`: `%s`\n' "$cargo_audit_version"
    printf -- '- expected `cargo-deny`: `%s`\n' "$EXPECTED_CARGO_DENY_VERSION"
    printf -- '- observed `cargo deny --version`: `%s`\n' "$cargo_deny_version"
    printf -- '- `rustc --version`: `%s`\n' "$rustc_version"
    printf -- '- `cargo --version`: `%s`\n\n' "$cargo_version"

    printf '## Verification Command Contract\n\n'
    printf 'These commands are the required verification contract for this release candidate. This section records command names and does not prove that the commands completed successfully; use a completed gate log or current `bash scripts/verify_phase_gate.sh` run for pass/fail evidence.\n\n'
    printf -- '- `cargo fmt --all --check`\n'
    printf -- '- `cargo clippy --workspace --all-targets --all-features --no-deps`\n'
    printf -- '- `cargo test --workspace --all-features --release --verbose`\n'
    printf -- '- `bash scripts/verify_assurance_replay.sh`\n'
    printf -- '- `cargo audit --deny warnings`\n'
    printf -- '- `cargo deny check`\n'
    printf -- '- `cargo build -p dexios --profile release`\n'
    printf -- '- `bash scripts/verify_cli_surface.sh`\n'
    printf -- '- `bash scripts/generate_release_manifest.sh --output %q' "$output"
    for asset in "${assets[@]}"; do
        printf ' --asset %q' "$asset"
    done
    [[ -z "$tag" ]] || printf ' --tag %q' "$tag"
    [[ "$allow_dirty" -eq 0 ]] || printf ' --allow-dirty'
    printf '`\n'
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

    printf '## RC Evidence\n\n'
    printf 'The release candidate closeout evidence artifact is recorded at\n'
    printf '`release-evidence/RC-CLOSEOUT.md` in the source tree. That document names the\n'
    printf 'blocker-to-check traceability matrix, accepted residual risks, platform limits,\n'
    printf 'non-goals, property/fuzz coverage decision, and performance gate status for the\n'
    printf 'release candidate.\n'
    printf 'This manifest entry records the reference; it does not independently verify the\n'
    printf 'matrix entries. Use a completed `bash scripts/verify_phase_gate.sh` run for\n'
    printf 'pass/fail evidence against the contracts named in RC-CLOSEOUT.md.\n\n'

    printf '## Claim Limits\n\n'
    printf 'This manifest records local evidence for one release candidate. It does not claim bit-for-bit reproducibility, signing trust, SBOM completeness, SBOM protection, supply-chain prevention, completed verification, or runtime safety beyond separately completed gate results for this candidate.\n'
} >"$output"

printf 'Release manifest written to %s\n' "$output"
