#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

require_tool() {
    local tool=$1
    local hint=$2

    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool not found: $tool" >&2
        echo "Install hint: $hint" >&2
        exit 2
    fi
}

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

require_tool cargo-audit "cargo install cargo-audit --locked --version 0.22.1"
require_tool mdbook "cargo install mdbook --locked"

run cargo fmt --all --check
run cargo clippy --workspace --all-targets --all-features --no-deps
run cargo test --workspace --all-features --release --verbose
run cargo audit
run bash scripts/verify_repo_hygiene.sh
run mdbook build
