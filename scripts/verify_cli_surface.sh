#!/usr/bin/env bash

set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$REPO_ROOT/target/release-lto/dexios}"

if [[ ! -x "$BIN" ]]; then
    echo "Binary not found or not executable: $BIN" >&2
    echo "Build it first, for example: cargo build -p dexios --profile release-lto" >&2
    exit 2
fi

FAILURES=0
ROOT="$(mktemp -d /tmp/dexios-cli-surface.XXXXXX)"

cleanup() {
    if [[ "${KEEP_TMP:-0}" == "1" || "$FAILURES" -ne 0 ]]; then
        echo "Artifacts kept at: $ROOT"
    else
        rm -rf "$ROOT"
    fi
}
trap cleanup EXIT

pass() {
    printf 'PASS %s\n' "$1"
}

fail() {
    printf 'FAIL %s: %s\n' "$1" "$2" >&2
    FAILURES=$((FAILURES + 1))
}

contains_file() {
    local file=$1
    local needle=$2
    local msg=$3
    grep -F "$needle" "$file" >/dev/null || {
        echo "$msg" >&2
        return 1
    }
}

exists() {
    local path=$1
    local msg=$2
    [[ -e "$path" ]] || {
        echo "$msg" >&2
        return 1
    }
}

not_exists() {
    local path=$1
    local msg=$2
    [[ ! -e "$path" ]] || {
        echo "$msg" >&2
        return 1
    }
}

file_eq() {
    local left=$1
    local right=$2
    local msg=$3
    cmp -s "$left" "$right" || {
        echo "$msg" >&2
        return 1
    }
}

run_case() {
    local name=$1
    shift

    if "$@"; then
        pass "$name"
    else
        fail "$name" "see stderr above"
    fi
}

case_encrypt_decrypt_env_hash_erase() {
    local dir="$ROOT/enc"
    mkdir -p "$dir"
    printf 'alpha\nbeta\n' > "$dir/plain.txt"

    DEXIOS_KEY=12345678 "$BIN" encrypt -f --hash --erase "$dir/plain.txt" "$dir/plain.enc" > "$dir/encrypt.stdout" || return 1
    not_exists "$dir/plain.txt" "encrypt --erase should remove plaintext input" || return 1
    exists "$dir/plain.enc" "encrypt should create cipher file" || return 1
    contains_file "$dir/encrypt.stdout" "$dir/plain.enc:" "encrypt --hash should print output hash" || return 1

    DEXIOS_KEY=12345678 "$BIN" decrypt -f --hash --erase "$dir/plain.enc" "$dir/plain.out" > "$dir/decrypt.stdout" || return 1
    not_exists "$dir/plain.enc" "decrypt --erase should remove encrypted input" || return 1
    exists "$dir/plain.out" "decrypt should create plaintext output" || return 1
    contains_file "$dir/decrypt.stdout" "$dir/plain.enc:" "decrypt --hash should print input hash" || return 1
    contains_file "$dir/plain.out" "alpha" "decrypted output should contain original content" || return 1
    contains_file "$dir/plain.out" "beta" "decrypted output should contain second line" || return 1
}

case_encrypt_decrypt_keyfile_detached_aes_argon() {
    local dir="$ROOT/keyfile"
    mkdir -p "$dir"
    printf 'super-secret\n' > "$dir/plain.txt"
    printf 'key-material-1' > "$dir/key.bin"

    "$BIN" encrypt -f -k "$dir/key.bin" --header "$dir/plain.hdr" --aes --argon "$dir/plain.txt" "$dir/plain.enc" || return 1
    exists "$dir/plain.enc" "encrypt keyfile detached header should create cipher" || return 1
    exists "$dir/plain.hdr" "encrypt keyfile detached header should create header" || return 1

    "$BIN" decrypt -f -k "$dir/key.bin" --header "$dir/plain.hdr" "$dir/plain.enc" "$dir/plain.out" || return 1
    file_eq "$dir/plain.txt" "$dir/plain.out" "keyfile detached header decrypt should round-trip" || return 1
}

case_encrypt_auto_generated_passphrase() {
    local dir="$ROOT/auto"
    local auto_key
    mkdir -p "$dir"
    printf 'generated passphrase path\n' > "$dir/plain.txt"

    "$BIN" encrypt -f --auto=4 "$dir/plain.txt" "$dir/plain.enc" > "$dir/auto.stdout" || return 1
    auto_key="$(sed -n 's/^\[-\] Your generated passphrase is: //p' "$dir/auto.stdout" | tail -n 1)"
    [[ -n "$auto_key" ]] || {
        echo "encrypt --auto should print generated passphrase" >&2
        return 1
    }

    DEXIOS_KEY="$auto_key" "$BIN" decrypt -f "$dir/plain.enc" "$dir/plain.out" || return 1
    file_eq "$dir/plain.txt" "$dir/plain.out" "auto-generated passphrase decrypt should round-trip" || return 1
}

case_hash_subcommand() {
    local out="$ROOT/hash.stdout"
    "$BIN" hash "$ROOT/auto/plain.txt" "$ROOT/keyfile/plain.enc" > "$out" || return 1
    contains_file "$out" "$ROOT/auto/plain.txt:" "hash should print plaintext hash line" || return 1
    contains_file "$out" "$ROOT/keyfile/plain.enc:" "hash should print encrypted hash line" || return 1
}

case_erase_subcommand() {
    local dir="$ROOT/erase"
    mkdir -p "$dir"
    printf 'erase me' > "$dir/file.txt"
    "$BIN" erase -f --passes=2 "$dir/file.txt" || return 1
    not_exists "$dir/file.txt" "erase should remove file" || return 1
}

case_header_subcommands() {
    local dir="$ROOT/header"
    mkdir -p "$dir"
    printf 'header-body\n' > "$dir/plain.txt"

    DEXIOS_KEY=12345678 "$BIN" encrypt -f "$dir/plain.txt" "$dir/plain.enc" || return 1

    "$BIN" header details "$dir/plain.enc" > "$dir/details-enc.stdout" || return 1
    contains_file "$dir/details-enc.stdout" "Header version:" "header details should describe encrypted file" || return 1

    "$BIN" header dump -f "$dir/plain.enc" "$dir/plain.hdr" || return 1
    exists "$dir/plain.hdr" "header dump should create header file" || return 1

    "$BIN" header details "$dir/plain.hdr" > "$dir/details-hdr.stdout" || return 1
    contains_file "$dir/details-hdr.stdout" "Header version:" "header details should describe dumped header" || return 1

    cp "$dir/plain.enc" "$dir/stripped.enc"
    "$BIN" header strip "$dir/stripped.enc" || return 1
    DEXIOS_KEY=12345678 "$BIN" decrypt -f --header "$dir/plain.hdr" "$dir/stripped.enc" "$dir/stripped-via-header.out" || return 1
    file_eq "$dir/plain.txt" "$dir/stripped-via-header.out" "decrypt with dumped header after strip should work" || return 1

    cp "$dir/stripped.enc" "$dir/restored.enc"
    "$BIN" header restore "$dir/plain.hdr" "$dir/restored.enc" || return 1
    DEXIOS_KEY=12345678 "$BIN" decrypt -f "$dir/restored.enc" "$dir/restored.out" || return 1
    file_eq "$dir/plain.txt" "$dir/restored.out" "header restore should make file decryptable again without detached header" || return 1
}

case_key_subcommands() {
    local dir="$ROOT/keyops"
    mkdir -p "$dir"
    printf 'old-key-material' > "$dir/old.key"
    printf 'new-key-material' > "$dir/new.key"
    printf 'changed-key-material' > "$dir/changed.key"
    printf 'key-body\n' > "$dir/plain.txt"

    "$BIN" encrypt -f -k "$dir/old.key" "$dir/plain.txt" "$dir/multi.enc" || return 1
    "$BIN" key verify -k "$dir/old.key" "$dir/multi.enc" || return 1
    "$BIN" key add -k "$dir/old.key" -n "$dir/new.key" "$dir/multi.enc" || return 1
    "$BIN" key verify -k "$dir/new.key" "$dir/multi.enc" || return 1
    "$BIN" key del -k "$dir/new.key" "$dir/multi.enc" || return 1

    if "$BIN" key verify -k "$dir/new.key" "$dir/multi.enc" >/dev/null 2>&1; then
        echo "deleted key should no longer verify" >&2
        return 1
    fi

    "$BIN" key verify -k "$dir/old.key" "$dir/multi.enc" || return 1

    "$BIN" encrypt -f -k "$dir/old.key" "$dir/plain.txt" "$dir/change.enc" || return 1
    "$BIN" key change -k "$dir/old.key" -n "$dir/changed.key" "$dir/change.enc" || return 1

    if "$BIN" key verify -k "$dir/old.key" "$dir/change.enc" >/dev/null 2>&1; then
        echo "changed old key should no longer verify" >&2
        return 1
    fi

    "$BIN" key verify -k "$dir/changed.key" "$dir/change.enc" || return 1
    "$BIN" decrypt -f -k "$dir/changed.key" "$dir/change.enc" "$dir/change.out" || return 1
    file_eq "$dir/plain.txt" "$dir/change.out" "key change should preserve decryptability with new key" || return 1
}

case_pack_unpack_complex_success_path() {
    local dir="$ROOT/packcomplex"
    mkdir -p "$dir/src/nested" "$dir/out"
    printf 'root-data\n' > "$dir/src/root.txt"
    printf 'nested-data\n' > "$dir/src/nested/inner.txt"
    printf 'pack-key-material' > "$dir/pack.key"

    (
        cd "$dir" &&
        "$BIN" pack -f -k pack.key --header pack.hdr --aes --argon --zstd --hash --erase src pack.enc > pack.stdout
    ) || return 1

    not_exists "$dir/src" "pack --erase should remove source directory tree" || return 1
    exists "$dir/pack.enc" "pack should produce encrypted archive" || return 1
    exists "$dir/pack.hdr" "pack detached header should exist" || return 1
    contains_file "$dir/pack.stdout" "pack.enc:" "pack --hash should print output hash" || return 1

    (
        cd "$dir" &&
        "$BIN" unpack -f -k pack.key --header pack.hdr --hash --verbose pack.enc out > unpack.stdout
    ) || return 1

    exists "$dir/out/src/root.txt" "unpack should restore packed root file" || return 1
    exists "$dir/out/src/nested/inner.txt" "unpack should restore nested file" || return 1
    contains_file "$dir/unpack.stdout" "[i] Extracting root.txt" "unpack --verbose should print extracted file names" || return 1
    contains_file "$dir/unpack.stdout" "pack.enc:" "unpack --hash should print archive hash" || return 1
}

case_unpack_erase_removes_archive() {
    local dir="$ROOT/unpackerase"
    mkdir -p "$dir/src" "$dir/out"
    printf 'erase-archive\n' > "$dir/src/file.txt"

    (
        cd "$dir" &&
        DEXIOS_KEY=12345678 "$BIN" pack -f src archive.enc > /dev/null &&
        DEXIOS_KEY=12345678 "$BIN" unpack -f --erase archive.enc out > /dev/null
    ) || return 1

    not_exists "$dir/archive.enc" "unpack --erase should remove archive input" || return 1
    exists "$dir/out/src/file.txt" "unpack --erase should still restore files" || return 1
}

case_pack_recursive_flag_compatibility_alias() {
    local dir="$ROOT/packflags"
    mkdir -p "$dir/src/nested/deeper" "$dir/out-no" "$dir/out-rec"
    printf 'top\n' > "$dir/src/top.txt"
    printf 'deep\n' > "$dir/src/nested/deeper/deep.txt"

    (
        cd "$dir" &&
        DEXIOS_KEY=12345678 "$BIN" pack -f src no_recursive.enc > no_recursive.stdout &&
        DEXIOS_KEY=12345678 "$BIN" pack -f -r src recursive.enc > recursive.stdout &&
        DEXIOS_KEY=12345678 "$BIN" unpack -f no_recursive.enc out-no > /dev/null &&
        DEXIOS_KEY=12345678 "$BIN" unpack -f recursive.enc out-rec > /dev/null
    ) || return 1

    exists "$dir/out-no/src/nested/deeper/deep.txt" "default pack should include deeply nested file" || return 1
    exists "$dir/out-rec/src/nested/deeper/deep.txt" "pack with --recursive should include deeply nested file" || return 1
}

case_pack_verbose_emits_output() {
    local dir="$ROOT/packverbose"
    mkdir -p "$dir/src/sub"
    printf 'x\n' > "$dir/src/a.txt"
    printf 'y\n' > "$dir/src/sub/b.txt"

    (
        cd "$dir" &&
        DEXIOS_KEY=12345678 "$BIN" pack -f -v src verbose.enc > verbose.stdout
    ) || return 1

    if [[ "$(wc -c < "$dir/verbose.stdout")" -eq 0 ]]; then
        echo "pack --verbose produced no output" >&2
        return 1
    fi
}

echo "Using binary: $BIN"
echo "Working root: $ROOT"

run_case "encrypt/decrypt env+hash+erase" case_encrypt_decrypt_env_hash_erase
run_case "encrypt/decrypt keyfile+detached+aes+argon" case_encrypt_decrypt_keyfile_detached_aes_argon
run_case "encrypt --auto" case_encrypt_auto_generated_passphrase
run_case "hash subcommand" case_hash_subcommand
run_case "erase subcommand" case_erase_subcommand
run_case "header subcommands" case_header_subcommands
run_case "key subcommands" case_key_subcommands
run_case "pack/unpack complex success path" case_pack_unpack_complex_success_path
run_case "unpack --erase" case_unpack_erase_removes_archive
run_case "pack --recursive compatibility alias" case_pack_recursive_flag_compatibility_alias
run_case "pack --verbose emits output" case_pack_verbose_emits_output

echo
if [[ "$FAILURES" -eq 0 ]]; then
    echo "All CLI surface checks passed."
    exit 0
fi

echo "$FAILURES CLI surface check(s) failed."
exit 1
