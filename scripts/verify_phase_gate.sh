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

verify_no_unsafe_crate_roots() {
    local crate_root
    local crate_roots=(
        "dexios/src/main.rs"
        "dexios-core/src/lib.rs"
        "dexios-domain/src/lib.rs"
    )

    for crate_root in "${crate_roots[@]}"; do
        if ! grep -Fxq '#![forbid(unsafe_code)]' "$crate_root"; then
            echo "Missing required crate-root guard in $crate_root: #![forbid(unsafe_code)]" >&2
            exit 1
        fi
    done
}

require_tool cargo-audit "cargo install cargo-audit --locked --version 0.22.1"
require_tool cargo-deny "cargo install cargo-deny --locked --version 0.19.6"
require_tool mdbook "cargo install mdbook --locked"

run verify_no_unsafe_crate_roots
run cargo fmt --all --check
run cargo clippy --workspace --all-targets --all-features --no-deps
run cargo test -p dexios-core --test stream_v1 --release
run cargo test -p dexios-core --test v1_header --release
run cargo test -p dexios-domain --test pack_paths --release
run cargo test -p dexios-domain --test unpack --release
run cargo test -p dexios-domain --test workflow_public_api --all-features --release
run cargo test -p dexios-domain --test archive_public_api --release
run cargo test -p dexios-domain --test workflow_errors --all-features --release
run cargo test -p dexios --test pack_cli_regressions --release
run cargo test -p dexios --test unpack_cli_regressions --release
run cargo test -p dexios --test delete_source_cli --release
run cargo test -p dexios --test workflow_error_cli --release
run cargo test -p dexios --test verification_gate_docs --release
run cargo test --workspace --all-features --release --verbose
run bash scripts/verify_assurance_replay.sh
run cargo audit --deny warnings
run cargo deny check
run cargo build -p dexios --profile release-lto
run bash scripts/verify_cli_surface.sh
run bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release-lto/dexios
run mdbook build
run git diff --exit-code -- docs
run bash scripts/verify_repo_hygiene.sh
run git diff --check
