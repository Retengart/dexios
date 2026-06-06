#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() {
    echo "Repository hygiene check failed: $*" >&2
    exit 1
}

PDF_BINARY_ATTRIBUTE='*.pdf binary'

is_release_sensitive_untracked_path() {
    local path=$1

    case "$path" in
        target/* | .local-tools/* | .local-tools/*)
            return 1
            ;;
    esac

    case "$path" in
        .gitattributes | \
        .github/workflows/* | \
        book/src/* | \
        docs/* | \
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

verify_pdf_attribute_policy() {
    git ls-files --error-unmatch .gitattributes >/dev/null 2>&1 \
        || fail ".gitattributes must be tracked for generated PDF review metadata"

    grep -Fxq "$PDF_BINARY_ATTRIBUTE" .gitattributes \
        || fail ".gitattributes must define the PDF binary attribute policy: $PDF_BINARY_ATTRIBUTE"
}

verify_release_sensitive_untracked_paths() {
    local line
    local path

    while IFS= read -r line; do
        [[ "$line" == '?? '* ]] || continue
        path=${line#'?? '}

        if is_release_sensitive_untracked_path "$path"; then
            fail "release-sensitive untracked path must be tracked; track or remove it before release-equivalent evidence: $path"
        fi
    done < <(git status --porcelain --untracked-files=all)
}

tracked_planning="$(git ls-files local-notes)"
[[ -n "$tracked_planning" ]] || fail "local-notes/ is not tracked by git"

! git check-ignore -q local-notes || fail "local-notes/ must not be gitignored (committed project state)"

verify_pdf_attribute_policy
verify_release_sensitive_untracked_paths

grep -F 'build-dir = "docs"' book.toml >/dev/null \
    || fail 'book.toml must keep build-dir = "docs"'

[[ -f CHANGELOG.md ]] || fail "CHANGELOG.md is missing"

if rg -n -i '(^|[^a-z])(see|read|requires?|depends on) +`?\local-notes/' \
    README.md CONTRIBUTING.md CHANGELOG.md book/src >/dev/null; then
    fail "tracked public docs must not require local-notes/ as public documentation"
fi

printf 'Repository hygiene checks passed.\n'
