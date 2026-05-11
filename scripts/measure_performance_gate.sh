#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCENARIO="all"
DRY_RUN=0
OUTPUT_ROOT="$REPO_ROOT/target/phase7-measurements"
WORK_ROOT="$OUTPUT_ROOT/work"
LOG_PATH="$OUTPUT_ROOT/measurement-$(date -u +%Y%m%dT%H%M%SZ).log"
BIN="$REPO_ROOT/target/release/dexios"

usage() {
    cat <<'USAGE'
Usage: scripts/measure_performance_gate.sh [--dry-run] [--scenario <name>]

Scenarios:
  kdf           Measure the release KDF regression test path.
  stream        Measure representative file encrypt/decrypt stream throughput.
  pack-unpack   Measure representative pack/unpack memory and elapsed time.
  temp-space    Measure temporary workspace size before and after pack/unpack.
  all           Run every scenario above.

Measurement logs are written under target/phase7-measurements/.
Use --dry-run to print the commands without creating fixtures or invoking dexios.
USAGE
}

die() {
    echo "measure_performance_gate.sh: $*" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --scenario)
            [[ $# -ge 2 ]] || die "--scenario requires a value"
            SCENARIO="$2"
            shift 2
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

case "$SCENARIO" in
    kdf|stream|pack-unpack|temp-space|all) ;;
    *) die "unknown scenario: $SCENARIO" ;;
esac

print_cmd() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
}

dry_run() {
    print_cmd "$@"
}

run_timed() {
    local label=$1
    shift

    {
        printf '\n## %s\n' "$label"
        print_cmd "$@"
    } | tee -a "$LOG_PATH"

    if [[ -x /usr/bin/time ]]; then
        /usr/bin/time -v "$@" 2>&1 | tee -a "$LOG_PATH"
        return "${PIPESTATUS[0]}"
    fi

    echo "/usr/bin/time -v not available; using shell elapsed seconds only." | tee -a "$LOG_PATH"
    local start
    local end
    start="$(date +%s)"
    "$@" 2>&1 | tee -a "$LOG_PATH"
    local status="${PIPESTATUS[0]}"
    end="$(date +%s)"
    echo "elapsed_seconds=$((end - start))" | tee -a "$LOG_PATH"
    return "$status"
}

prepare_real_run() {
    mkdir -p "$WORK_ROOT"
    {
        echo "Dexios Phase 7 measurement gate"
        echo "repo=$REPO_ROOT"
        echo "scenario=$SCENARIO"
        echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "output=$LOG_PATH"
        echo
    } > "$LOG_PATH"
    echo "Measurement output: $LOG_PATH"
}

scenario_kdf() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo test -p dexios-core --test key_derivation --release -- --nocapture
        return
    fi

    run_timed "kdf" cargo test -p dexios-core --test key_derivation --release -- --nocapture
}

build_cli() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        return
    fi

    run_timed "build dexios release binary" cargo build -p dexios --release
}

scenario_stream() {
    local dir="$WORK_ROOT/stream"
    local plain="$dir/plain.bin"
    local enc="$dir/plain.enc"
    local out="$dir/plain.out"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        dry_run mkdir -p "$dir"
        dry_run dd if=/dev/urandom of="$plain" bs=1M count=16
        dry_run env DEXIOS_KEY=12345678 "$BIN" encrypt -f "$plain" "$enc"
        dry_run env DEXIOS_KEY=12345678 "$BIN" decrypt -f "$enc" "$out"
        dry_run cmp "$plain" "$out"
        return
    fi

    build_cli
    mkdir -p "$dir"
    run_timed "stream fixture generation" dd if=/dev/urandom of="$plain" bs=1M count=16
    run_timed "stream encrypt throughput" env DEXIOS_KEY=12345678 "$BIN" encrypt -f "$plain" "$enc"
    run_timed "stream decrypt throughput" env DEXIOS_KEY=12345678 "$BIN" decrypt -f "$enc" "$out"
    run_timed "stream roundtrip compare" cmp "$plain" "$out"
}

scenario_pack_unpack() {
    local dir="$WORK_ROOT/pack-unpack"
    local src="$dir/src"
    local enc="$dir/archive.enc"
    local out="$dir/out"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        dry_run mkdir -p "$src/nested" "$out"
        dry_run dd if=/dev/urandom of="$src/root.bin" bs=1M count=8
        dry_run dd if=/dev/urandom of="$src/nested/inner.bin" bs=1M count=8
        dry_run env DEXIOS_KEY=12345678 "$BIN" pack -f "$src" "$enc"
        dry_run env DEXIOS_KEY=12345678 "$BIN" unpack -f "$enc" "$out"
        dry_run test -f "$out/src/root.bin"
        dry_run test -f "$out/src/nested/inner.bin"
        return
    fi

    build_cli
    mkdir -p "$src/nested" "$out"
    run_timed "pack/unpack fixture root" dd if=/dev/urandom of="$src/root.bin" bs=1M count=8
    run_timed "pack/unpack fixture nested" dd if=/dev/urandom of="$src/nested/inner.bin" bs=1M count=8
    run_timed "pack memory and elapsed time" env DEXIOS_KEY=12345678 "$BIN" pack -f "$src" "$enc"
    run_timed "unpack memory and elapsed time" env DEXIOS_KEY=12345678 "$BIN" unpack -f "$enc" "$out"
    run_timed "pack/unpack restored root" test -f "$out/src/root.bin"
    run_timed "pack/unpack restored nested" test -f "$out/src/nested/inner.bin"
}

scenario_temp_space() {
    local dir="$WORK_ROOT/temp-space"
    local src="$dir/src"
    local enc="$dir/archive.enc"
    local out="$dir/out"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        dry_run mkdir -p "$src" "$out"
        dry_run du -sk "$WORK_ROOT"
        dry_run dd if=/dev/urandom of="$src/blob.bin" bs=1M count=16
        dry_run env DEXIOS_KEY=12345678 "$BIN" pack -f "$src" "$enc"
        dry_run du -sk "$WORK_ROOT"
        dry_run env DEXIOS_KEY=12345678 "$BIN" unpack -f "$enc" "$out"
        dry_run du -sk "$WORK_ROOT"
        return
    fi

    build_cli
    mkdir -p "$src" "$out"
    run_timed "temp-space before fixture" du -sk "$WORK_ROOT"
    run_timed "temp-space fixture" dd if=/dev/urandom of="$src/blob.bin" bs=1M count=16
    run_timed "temp-space pack" env DEXIOS_KEY=12345678 "$BIN" pack -f "$src" "$enc"
    run_timed "temp-space after pack" du -sk "$WORK_ROOT"
    run_timed "temp-space unpack" env DEXIOS_KEY=12345678 "$BIN" unpack -f "$enc" "$out"
    run_timed "temp-space after unpack" du -sk "$WORK_ROOT"
}

run_scenario() {
    case "$1" in
        kdf) scenario_kdf ;;
        stream) scenario_stream ;;
        pack-unpack) scenario_pack_unpack ;;
        temp-space) scenario_temp_space ;;
    esac
}

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run only. Measurement output would be under: target/phase7-measurements/"
else
    prepare_real_run
fi

if [[ "$SCENARIO" == "all" ]]; then
    for item in kdf stream pack-unpack temp-space; do
        run_scenario "$item"
    done
else
    run_scenario "$SCENARIO"
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
    echo "Measurement output: $LOG_PATH"
fi
