#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

require_tool() {
    local tool=$1
    local hint=$2

    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool not found: $tool" >&2
        echo "Install/cache hint: $hint" >&2
        exit 2
    fi
}

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

require_tool cargo "Install Cargo and ensure locked dependencies are already cached before running this offline replay."

export CARGO_NET_OFFLINE=true

run cargo test --locked --offline -p dexios-core --test v1_header --release
run cargo test --locked --offline -p dexios-core --test stream_v1 --release
run cargo test --locked --offline -p dexios-core --test key_derivation --release
run cargo test --locked --offline -p dexios-domain --test keyslots_v1 --release
run cargo test --locked --offline -p dexios-domain --test decrypt_workflow_errors --release
run cargo test --locked --offline -p dexios-domain --test unpack --release
run cargo test --locked --offline -p dexios --test decrypt_cli_regressions --release
run cargo test --locked --offline -p dexios --test unpack_cli_regressions --release
