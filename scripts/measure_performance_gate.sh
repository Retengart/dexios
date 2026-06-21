#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCENARIO="all"
DRY_RUN=0
KDF_MAX_SECONDS="${DEXIOS_KDF_MAX_SECONDS:-}"
STREAM_ENCRYPT_MAX_SECONDS="${DEXIOS_STREAM_ENCRYPT_MAX_SECONDS:-}"
STREAM_DECRYPT_MAX_SECONDS="${DEXIOS_STREAM_DECRYPT_MAX_SECONDS:-}"
PACK_MAX_SECONDS="${DEXIOS_PACK_MAX_SECONDS:-}"
UNPACK_MAX_SECONDS="${DEXIOS_UNPACK_MAX_SECONDS:-}"
TEMP_SPACE_MAX_KIB="${DEXIOS_TEMP_SPACE_MAX_KIB:-}"
LAST_ELAPSED_SECONDS=""
MAX_OBSERVED_TEMP_SPACE_KIB=0
OUTPUT_ROOT="$REPO_ROOT/target/phase7-measurements"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
WORK_ROOT="$OUTPUT_ROOT/work/$RUN_ID"
LOG_PATH="$OUTPUT_ROOT/measurement-$RUN_ID.log"
BIN="$REPO_ROOT/target/release/dexios"

usage() {
    cat <<'USAGE'
Usage: scripts/measure_performance_gate.sh [--dry-run] [--scenario <name>] [threshold options]

Scenarios:
  kdf           Measure the release KDF regression test path.
  stream        Measure representative file encrypt/decrypt stream throughput.
  pack-unpack   Measure representative pack/unpack memory and elapsed time.
  temp-space    Measure temporary workspace size before and after pack/unpack.
  all           Run every scenario above.

Measurement logs are written under target/phase7-measurements/.
Use thresholds for focused release checks:
  --max-kdf-seconds <seconds>             or DEXIOS_KDF_MAX_SECONDS
  --max-stream-encrypt-seconds <seconds>  or DEXIOS_STREAM_ENCRYPT_MAX_SECONDS
  --max-stream-decrypt-seconds <seconds>  or DEXIOS_STREAM_DECRYPT_MAX_SECONDS
  --max-pack-seconds <seconds>            or DEXIOS_PACK_MAX_SECONDS
  --max-unpack-seconds <seconds>          or DEXIOS_UNPACK_MAX_SECONDS
  --max-temp-space-kib <kib>              or DEXIOS_TEMP_SPACE_MAX_KIB
Use --dry-run to print the commands without creating fixtures or invoking dexios.
USAGE
}

die() {
    echo "measure_performance_gate.sh: $*" >&2
    exit 2
}

validate_seconds() {
    local value=$1
    [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "seconds must be a non-negative number: $value"
}

validate_positive_integer() {
    local value=$1
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "KiB threshold must be a positive integer: $value"
}

parse_time_verbose_elapsed_seconds() {
    local time_output=$1

    awk '
        /Elapsed \(wall clock\) time/ {
            value = $NF
            parts_count = split(value, parts, ":")
            if (parts_count == 3) {
                seconds = (parts[1] * 3600) + (parts[2] * 60) + parts[3]
            } else if (parts_count == 2) {
                seconds = (parts[1] * 60) + parts[2]
            } else {
                seconds = value
            }
            printf "%.3f\n", seconds
            found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$time_output"
}

exceeds_threshold() {
    local elapsed=$1
    local threshold=$2

    awk -v elapsed="$elapsed" -v threshold="$threshold" 'BEGIN { exit(elapsed > threshold ? 0 : 1) }'
}

validate_thresholds() {
    for value in \
        "$KDF_MAX_SECONDS" \
        "$STREAM_ENCRYPT_MAX_SECONDS" \
        "$STREAM_DECRYPT_MAX_SECONDS" \
        "$PACK_MAX_SECONDS" \
        "$UNPACK_MAX_SECONDS"; do
        if [[ -n "$value" ]]; then
            validate_seconds "$value"
        fi
    done

    if [[ -n "$TEMP_SPACE_MAX_KIB" ]]; then
        validate_positive_integer "$TEMP_SPACE_MAX_KIB"
    fi
}

threshold_value() {
    local value=$1
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "unset"
    fi
}

print_threshold_context() {
    if [[ "$LOG_PATH" == "/dev/stdout" ]]; then
        echo "Threshold context:"
        echo "  kdf_max_seconds=$(threshold_value "$KDF_MAX_SECONDS")"
        echo "  stream_encrypt_max_seconds=$(threshold_value "$STREAM_ENCRYPT_MAX_SECONDS")"
        echo "  stream_decrypt_max_seconds=$(threshold_value "$STREAM_DECRYPT_MAX_SECONDS")"
        echo "  pack_max_seconds=$(threshold_value "$PACK_MAX_SECONDS")"
        echo "  unpack_max_seconds=$(threshold_value "$UNPACK_MAX_SECONDS")"
        echo "  temp_space_max_kib=$(threshold_value "$TEMP_SPACE_MAX_KIB")"
        return
    fi

    {
        echo "Threshold context:"
        echo "  kdf_max_seconds=$(threshold_value "$KDF_MAX_SECONDS")"
        echo "  stream_encrypt_max_seconds=$(threshold_value "$STREAM_ENCRYPT_MAX_SECONDS")"
        echo "  stream_decrypt_max_seconds=$(threshold_value "$STREAM_DECRYPT_MAX_SECONDS")"
        echo "  pack_max_seconds=$(threshold_value "$PACK_MAX_SECONDS")"
        echo "  unpack_max_seconds=$(threshold_value "$UNPACK_MAX_SECONDS")"
        echo "  temp_space_max_kib=$(threshold_value "$TEMP_SPACE_MAX_KIB")"
    } | tee -a "$LOG_PATH"
}

check_elapsed_threshold() {
    local label=$1
    local threshold=$2

    if [[ -z "$threshold" ]]; then
        return 0
    fi

    if exceeds_threshold "$LAST_ELAPSED_SECONDS" "$threshold"; then
        echo "threshold failure: scenario=$SCENARIO operation=\"$label\" measured_seconds=$LAST_ELAPSED_SECONDS threshold_seconds=$threshold log_path=$LOG_PATH" | tee -a "$LOG_PATH" >&2
        return 1
    fi

    echo "threshold ok: scenario=$SCENARIO operation=\"$label\" measured_seconds=$LAST_ELAPSED_SECONDS threshold_seconds=$threshold log_path=$LOG_PATH" | tee -a "$LOG_PATH"
}

record_temp_space_observed() {
    local label=$1
    local observed_root=$2
    local observed

    observed="$(du -sk "$observed_root" | awk '{print $1}')"
    if (( observed > MAX_OBSERVED_TEMP_SPACE_KIB )); then
        MAX_OBSERVED_TEMP_SPACE_KIB="$observed"
    fi

    echo "temp_space_observed: scenario=$SCENARIO operation=\"$label\" measured_kib=$observed max_observed_kib=$MAX_OBSERVED_TEMP_SPACE_KIB measured_path=$observed_root log_path=$LOG_PATH" | tee -a "$LOG_PATH"

    if [[ -n "$TEMP_SPACE_MAX_KIB" ]] && (( MAX_OBSERVED_TEMP_SPACE_KIB > TEMP_SPACE_MAX_KIB )); then
        echo "threshold failure: scenario=$SCENARIO operation=\"$label\" measured_kib=$MAX_OBSERVED_TEMP_SPACE_KIB threshold_kib=$TEMP_SPACE_MAX_KIB log_path=$LOG_PATH" | tee -a "$LOG_PATH" >&2
        return 1
    fi
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
        --max-kdf-seconds)
            [[ $# -ge 2 ]] || die "--max-kdf-seconds requires a value"
            KDF_MAX_SECONDS="$2"
            shift 2
            ;;
        --max-stream-encrypt-seconds)
            [[ $# -ge 2 ]] || die "--max-stream-encrypt-seconds requires a value"
            STREAM_ENCRYPT_MAX_SECONDS="$2"
            shift 2
            ;;
        --max-stream-decrypt-seconds)
            [[ $# -ge 2 ]] || die "--max-stream-decrypt-seconds requires a value"
            STREAM_DECRYPT_MAX_SECONDS="$2"
            shift 2
            ;;
        --max-pack-seconds)
            [[ $# -ge 2 ]] || die "--max-pack-seconds requires a value"
            PACK_MAX_SECONDS="$2"
            shift 2
            ;;
        --max-unpack-seconds)
            [[ $# -ge 2 ]] || die "--max-unpack-seconds requires a value"
            UNPACK_MAX_SECONDS="$2"
            shift 2
            ;;
        --max-temp-space-kib)
            [[ $# -ge 2 ]] || die "--max-temp-space-kib requires a value"
            TEMP_SPACE_MAX_KIB="$2"
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

validate_thresholds

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
    local start
    local end
    local status
    local time_output
    shift

    LAST_ELAPSED_SECONDS=""

    {
        printf '\n## %s\n' "$label"
        print_cmd "$@"
    } | tee -a "$LOG_PATH"

    start="$(date +%s)"
    if [[ -x /usr/bin/time ]]; then
        time_output="$(mktemp "$OUTPUT_ROOT/time-output.XXXXXX")"
        set +e
        /usr/bin/time -v "$@" 2>&1 | tee -a "$LOG_PATH" "$time_output"
        status="${PIPESTATUS[0]}"
        set -e
        LAST_ELAPSED_SECONDS="$(parse_time_verbose_elapsed_seconds "$time_output" || true)"
        rm -f "$time_output"
        if [[ -z "$LAST_ELAPSED_SECONDS" ]]; then
            end="$(date +%s)"
            LAST_ELAPSED_SECONDS="$((end - start))"
        fi
        echo "elapsed_seconds=$LAST_ELAPSED_SECONDS" | tee -a "$LOG_PATH"
        return "$status"
    fi

    echo "/usr/bin/time -v not available; using shell elapsed seconds only." | tee -a "$LOG_PATH"
    start="$(date +%s)"
    set +e
    "$@" 2>&1 | tee -a "$LOG_PATH"
    status="${PIPESTATUS[0]}"
    set -e
    end="$(date +%s)"
    LAST_ELAPSED_SECONDS="$((end - start))"
    echo "elapsed_seconds=$LAST_ELAPSED_SECONDS" | tee -a "$LOG_PATH"
    return "$status"
}

prepare_real_run() {
    mkdir -p "$WORK_ROOT"
    {
        echo "Dexios measurement gate"
        echo "repo=$REPO_ROOT"
        echo "scenario=$SCENARIO"
        echo "work_root=$WORK_ROOT"
        echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "output=$LOG_PATH"
        echo "uname=$(uname -a)"
        echo "rustc=$(rustc -Vv | tr '\n' ';')"
        echo "cargo=$(cargo -V)"
        if [[ -r /proc/cpuinfo ]]; then
            awk -F: '/model name/ { value=$2; sub(/^[[:space:]]+/, "", value); print "cpu_model=" value; exit }' /proc/cpuinfo
        fi
        if [[ -r /proc/meminfo ]]; then
            awk -F: '/MemTotal/ { value=$2; sub(/^[[:space:]]+/, "", value); print "mem_total=" value; exit }' /proc/meminfo
        fi
        if [[ -n "$KDF_MAX_SECONDS" ]]; then
            echo "kdf_max_seconds=$KDF_MAX_SECONDS"
        fi
        if [[ -n "$STREAM_ENCRYPT_MAX_SECONDS" ]]; then
            echo "stream_encrypt_max_seconds=$STREAM_ENCRYPT_MAX_SECONDS"
        fi
        if [[ -n "$STREAM_DECRYPT_MAX_SECONDS" ]]; then
            echo "stream_decrypt_max_seconds=$STREAM_DECRYPT_MAX_SECONDS"
        fi
        if [[ -n "$PACK_MAX_SECONDS" ]]; then
            echo "pack_max_seconds=$PACK_MAX_SECONDS"
        fi
        if [[ -n "$UNPACK_MAX_SECONDS" ]]; then
            echo "unpack_max_seconds=$UNPACK_MAX_SECONDS"
        fi
        if [[ -n "$TEMP_SPACE_MAX_KIB" ]]; then
            echo "temp_space_max_kib=$TEMP_SPACE_MAX_KIB"
        fi
        echo
    } > "$LOG_PATH"
    echo "Measurement output: $LOG_PATH"
    print_threshold_context
}

scenario_kdf() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        if [[ -n "$KDF_MAX_SECONDS" ]]; then
            echo "KDF threshold: max ${KDF_MAX_SECONDS}s"
        fi
        dry_run cargo test -p dexios-core --test key_derivation --release -- --nocapture
        return
    fi

    if ! run_timed "kdf" cargo test -p dexios-core --test key_derivation --release -- --nocapture; then
        return 1
    fi

    if [[ -n "$KDF_MAX_SECONDS" ]]; then
        check_elapsed_threshold "kdf" "$KDF_MAX_SECONDS"
    fi
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
    local key="$dir/key.bin"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        dry_run mkdir -p "$dir"
        dry_run printf 12345678 ">" "$key"
        dry_run dd if=/dev/urandom of="$plain" bs=1M count=16
        dry_run "$BIN" encrypt -f -k "$key" "$plain" "$enc"
        dry_run "$BIN" decrypt -f -k "$key" "$enc" "$out"
        dry_run cmp "$plain" "$out"
        return
    fi

    build_cli
    mkdir -p "$dir"
    printf '12345678' > "$key"
    run_timed "stream fixture generation" dd if=/dev/urandom of="$plain" bs=1M count=16
    run_timed "stream encrypt throughput" "$BIN" encrypt -f -k "$key" "$plain" "$enc"
    check_elapsed_threshold "stream encrypt throughput" "$STREAM_ENCRYPT_MAX_SECONDS"
    run_timed "stream decrypt throughput" "$BIN" decrypt -f -k "$key" "$enc" "$out"
    check_elapsed_threshold "stream decrypt throughput" "$STREAM_DECRYPT_MAX_SECONDS"
    run_timed "stream roundtrip compare" cmp "$plain" "$out"
}

scenario_pack_unpack() {
    local dir="$WORK_ROOT/pack-unpack"
    local src="$dir/src"
    local enc="$dir/archive.enc"
    local out="$dir/out"
    local key="$dir/key.bin"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        dry_run mkdir -p "$src/nested" "$out"
        dry_run printf 12345678 ">" "$key"
        dry_run dd if=/dev/urandom of="$src/root.bin" bs=1M count=8
        dry_run dd if=/dev/urandom of="$src/nested/inner.bin" bs=1M count=8
        dry_run "$BIN" pack -f -k "$key" "$src" "$enc"
        dry_run "$BIN" unpack -f -k "$key" "$enc" "$out"
        dry_run test -f "$out/src/root.bin"
        dry_run test -f "$out/src/nested/inner.bin"
        return
    fi

    build_cli
    mkdir -p "$src/nested" "$out"
    printf '12345678' > "$key"
    run_timed "pack/unpack fixture root" dd if=/dev/urandom of="$src/root.bin" bs=1M count=8
    run_timed "pack/unpack fixture nested" dd if=/dev/urandom of="$src/nested/inner.bin" bs=1M count=8
    run_timed "pack memory and elapsed time" "$BIN" pack -f -k "$key" "$src" "$enc"
    check_elapsed_threshold "pack memory and elapsed time" "$PACK_MAX_SECONDS"
    run_timed "unpack memory and elapsed time" "$BIN" unpack -f -k "$key" "$enc" "$out"
    check_elapsed_threshold "unpack memory and elapsed time" "$UNPACK_MAX_SECONDS"
    run_timed "pack/unpack restored root" test -f "$out/src/root.bin"
    run_timed "pack/unpack restored nested" test -f "$out/src/nested/inner.bin"
}

scenario_temp_space() {
    local dir="$WORK_ROOT/temp-space"
    local src="$dir/src"
    local enc="$dir/archive.enc"
    local out="$dir/out"
    local key="$dir/key.bin"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        dry_run cargo build -p dexios --release
        dry_run mkdir -p "$src" "$out"
        dry_run printf 12345678 ">" "$key"
        dry_run du -sk "$dir"
        dry_run dd if=/dev/urandom of="$src/blob.bin" bs=1M count=16
        dry_run "$BIN" pack -f -k "$key" "$src" "$enc"
        dry_run du -sk "$dir"
        dry_run "$BIN" unpack -f -k "$key" "$enc" "$out"
        dry_run du -sk "$dir"
        return
    fi

    build_cli
    mkdir -p "$src" "$out"
    printf '12345678' > "$key"
    run_timed "temp-space before fixture" du -sk "$dir"
    run_timed "temp-space fixture" dd if=/dev/urandom of="$src/blob.bin" bs=1M count=16
    run_timed "temp-space pack" "$BIN" pack -f -k "$key" "$src" "$enc"
    run_timed "temp-space after pack" du -sk "$dir"
    record_temp_space_observed "temp-space after pack" "$dir"
    run_timed "temp-space unpack" "$BIN" unpack -f -k "$key" "$enc" "$out"
    run_timed "temp-space after unpack" du -sk "$dir"
    record_temp_space_observed "temp-space after unpack" "$dir"
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
    LOG_PATH=/dev/stdout print_threshold_context
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
