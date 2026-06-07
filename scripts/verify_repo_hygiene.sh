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

verify_local_scratch_policy() {
    local tracked_local_scratch
    local ignored_path

    tracked_local_scratch="$(git ls-files local-notes local-plans .local-tools)"
    [[ -z "$tracked_local_scratch" ]] \
        || fail "local scratch path is tracked by git: $tracked_local_scratch"

    for ignored_path in local-notes local-plans .local-tools; do
        git check-ignore -q "$ignored_path" || git check-ignore -q "$ignored_path/" \
            || fail "local scratch path must be ignored: $ignored_path"
    done
}

tracked_generated_docs="$(git ls-files docs)"
[[ -z "$tracked_generated_docs" ]] \
    || fail "generated docs/ output must not be tracked; keep mdBook sources under book/src/"

verify_pdf_attribute_policy
verify_local_scratch_policy
verify_release_sensitive_untracked_paths

grep -F 'build-dir = "target/mdbook"' book.toml >/dev/null \
    || fail 'book.toml must keep build-dir = "target/mdbook"'

grep -Fxq '/docs/' .gitignore \
    || fail ".gitignore must ignore generated mdBook output at /docs/"

[[ -f CHANGELOG.md ]] || fail "CHANGELOG.md is missing"

if rg -n -i '(^|[^a-z])(see|read|requires?|depends on) +`?(local-notes|local-plans)/' \
    README.md CONTRIBUTING.md CHANGELOG.md book/src >/dev/null; then
    fail "tracked public docs must not require local-only working notes as public documentation"
fi

printf 'Repository hygiene checks passed.\n'
