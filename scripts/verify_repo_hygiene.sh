#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() {
    echo "Repository hygiene check failed: $*" >&2
    exit 1
}

tracked_planning="$(git ls-files local-notes)"
[[ -z "$tracked_planning" ]] || fail "local-notes/ is tracked by git"

git check-ignore -q local-notes || fail "local-notes/ is not ignored by git"

grep -F 'build-dir = "docs"' book.toml >/dev/null \
    || fail 'book.toml must keep build-dir = "docs"'

[[ -f CHANGELOG.md ]] || fail "CHANGELOG.md is missing"

if rg -n -i '(^|[^a-z])(see|read|requires?|depends on) +`?\local-notes/' \
    README.md CONTRIBUTING.md CHANGELOG.md book/src >/dev/null; then
    fail "tracked public docs must not require local-notes/ as public documentation"
fi

printf 'Repository hygiene checks passed.\n'
