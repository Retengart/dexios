#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

require_tool_version() {
    local executable=$1
    local label=$2
    local expected=$3
    local hint=$4
    shift 4

    if ! command -v "$executable" >/dev/null 2>&1; then
        echo "Required tool not found: $executable" >&2
        echo "Install hint: $hint" >&2
        exit 2
    fi

    local observed=""
    local observed_version=""
    if ! observed="$("$@" 2>/dev/null | head -1)"; then
        observed="unavailable"
    fi
    [[ -n "$observed" ]] || observed="unavailable"
    observed_version="$(observed_tool_version_token "$observed")"

    if [[ "$observed_version" != "$expected" ]]; then
        echo "Required $label version mismatch: expected $expected, observed $observed" >&2
        echo "Install hint: $hint" >&2
        exit 2
    fi
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

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

verify_no_unsafe_crate_roots() {
    local crate_root
    # Library crates must use #![forbid(unsafe_code)] — no override allowed.
    local forbid_crate_roots=(
        "dexios-core/src/lib.rs"
        "dexios-domain/src/lib.rs"
    )

    for crate_root in "${forbid_crate_roots[@]}"; do
        if ! grep -Fxq '#![forbid(unsafe_code)]' "$crate_root"; then
            echo "Missing required crate-root guard in $crate_root: #![forbid(unsafe_code)]" >&2
            exit 1
        fi
    done

    # The binary crate uses #![deny(unsafe_code)] (overridable with
    # #[allow(unsafe_code)]) for the DEXIOS_KEY scrub unsafe block.
    if ! grep -Fxq '#![deny(unsafe_code)]' "dexios/src/main.rs"; then
        echo "Missing required crate-root guard in dexios/src/main.rs: #![deny(unsafe_code)]" >&2
        exit 1
    fi
}

require_tool_version cargo-audit cargo-audit 0.22.1 "cargo install cargo-audit --locked --version 0.22.1" cargo audit --version
require_tool_version cargo-deny cargo-deny 0.19.6 "cargo install cargo-deny --locked --version 0.19.6" cargo deny --version
require_tool_version mdbook mdbook 0.5.3 "cargo install mdbook --locked --version 0.5.3" mdbook --version

run bash scripts/verify_repo_hygiene.sh
run cargo metadata --format-version=1 --locked --no-deps > /dev/null
run verify_no_unsafe_crate_roots
run cargo fmt --all --check
run cargo clippy --workspace --all-targets --all-features --no-deps --locked
run cargo test --locked -p dexios-core --test stream_v1 --release
run cargo test --locked -p dexios-core --test v1_header --release
run cargo test --locked -p dexios-domain --test pack_paths --release
run cargo test --locked -p dexios-domain --features test-support --test unpack_manifest_v1 --test unpack_path_identity --test unpack_commit_rollback --test unpack_symlink_revalidation --release
run cargo test --locked -p dexios-domain --features test-support --test cleanup_receipts --test path_identity --release
run cargo test --locked -p dexios-domain --test workflow_public_api --all-features --release
run cargo test --locked -p dexios-domain --test archive_public_api --release
run cargo test --locked -p dexios-domain --test workflow_errors --all-features --release
run cargo test --locked -p dexios-domain --features test-support --test transactions_staged_output --test transactions_linked_publication --test transactions_failure_hooks --test cleanup_receipts --test detached_publication --release
run cargo test --locked -p dexios --test encrypt_cli_regressions --test pack_cli_regressions --test delete_source_cli --test workflow_error_cli_boundary --test workflow_error_cli_archive --test workflow_error_cli_header_key --release
run cargo test --locked -p dexios-domain --features test-support --test workflow_public_api --test archive_public_api --test cleanup_receipts --test transactions_staged_output --test transactions_linked_publication --test transactions_failure_hooks --test workflow_errors --release
run cargo test --locked -p dexios-core --test public_api_footguns --release
run cargo test --locked -p dexios-domain --test header_restore --test header_workflow_errors --test keyslots_intent_v1 --test keyslots_crypto_v1 --test keyslots_mutation_v1 --test workflow_errors --release
run cargo test --locked -p dexios --test header_cli_regressions --test key_cli_regressions --release
run cargo test --locked -p dexios --test pack_cli_regressions --release
run cargo test --locked -p dexios --test unpack_cli_regressions --release
run cargo test --locked -p dexios --test delete_source_cli --release
run cargo test --locked -p dexios --test workflow_error_cli_boundary --test workflow_error_cli_archive --test workflow_error_cli_header_key --release
run cargo test --locked --workspace --all-features --release --verbose
run bash scripts/verify_assurance_replay.sh
run cargo audit --deny warnings
run cargo deny check
run cargo build --locked -p dexios --profile release
run bash scripts/verify_cli_surface.sh
run mdbook build --dest-dir target/mdbook
run bash scripts/verify_repo_hygiene.sh
run git diff --check
run bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release/dexios
