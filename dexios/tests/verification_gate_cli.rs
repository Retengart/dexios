#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::string_slice,
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::match_same_arms,
        clippy::items_after_statements,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_collect,
        clippy::manual_let_else,
        clippy::format_collect,
        clippy::case_sensitive_file_extension_comparisons,
        clippy::struct_excessive_bools,
        reason = "integration tests assert exact behavior and may panic on failure"
    )
)]
mod verification_gate_support;

use std::{path::Path, process::Command};

use verification_gate_support::*;

const REMOVED_CLI_SOURCE_PATTERNS: &[&str] =
    &["--aes", "--argon", "--zstd", "--erase", "\"$BIN\" erase"];

fn removed_token_positive_path_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();

    for (line_number, line) in source.lines().enumerate() {
        if !is_non_comment_line(line) || !line_contains_removed_cli_token(line) {
            continue;
        }
        if is_removed_surface_rejection_call(line) || is_removed_token_source_gate_definition(line)
        {
            continue;
        }

        violations.push(format!(
            "positive harness path at line {} contains removed CLI token: {}",
            line_number + 1,
            line
        ));
    }

    violations
}

fn line_contains_removed_cli_token(line: &str) -> bool {
    REMOVED_CLI_SOURCE_PATTERNS
        .iter()
        .any(|removed_token| line.contains(removed_token))
}

fn is_removed_surface_rejection_call(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("expect_rejected ") && trimmed.contains("\"$BIN\"")
}

fn is_removed_token_source_gate_definition(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("awk ")
        && line.contains("--aes|--argon|--zstd|--erase")
        && line.contains("$0 !~ /expect_rejected/")
}

fn removed_surface_helper_contract_violations(source: &str) -> Vec<String> {
    let helper_body = removed_surface_helper_body(source);
    let mut violations = Vec::new();

    if helper_body.to_ascii_lowercase().contains("error:") {
        violations
            .push("removed-surface helper accepts generic lowercase error fallback".to_owned());
    }

    for required in [
        "local expected_parser_rejection=$2",
        "grep -F \"$expected_parser_rejection\" \"$stderr\"",
        "echo \"Captured stdout: $stdout\" >&2",
        "echo \"Captured stderr: $stderr\" >&2",
        "cat \"$stderr\" >&2",
    ] {
        if !helper_body.contains(required) {
            violations.push(format!(
                "removed-surface helper must keep hardened contract anchor: {required}"
            ));
        }
    }

    violations
}

fn removed_surface_helper_body(source: &str) -> &str {
    source
        .split_once("expect_rejected() {")
        .expect("removed-surface rejection helper is present")
        .1
        .split_once("\n}\n")
        .expect("removed-surface rejection helper has a closing brace")
        .0
}

fn binary_selection_contract_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();

    for required in [
        "SELECTED_BIN=\"${1:-$REPO_ROOT/target/release-lto/dexios}\"",
        "resolve_selected_binary()",
        "if [[ \"$selected\" = /* ]]; then",
        "printf '%s\\n' \"$selected\"",
        "while [[ \"$selected\" == ./* ]]; do",
        "selected=\"${selected#./}\"",
        "printf '%s/%s\\n' \"$REPO_ROOT\" \"$selected\"",
        "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
    ] {
        if !source.contains(required) {
            violations.push(format!(
                "binary resolver must keep repo-root-normalized relative binary anchor: {required}"
            ));
        }
    }

    for (earlier, later) in [
        (
            "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
            "if [[ ! -x \"$BIN\" ]]",
        ),
        (
            "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
            "ROOT=\"$(mktemp -d /tmp/dexios-cli-surface.XXXXXX)\"",
        ),
        (
            "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
            "cd \"$dir\"",
        ),
    ] {
        if !source_occurs_before(source, earlier, later) {
            violations.push(format!(
                "binary resolver must normalize selected binary before smoke cwd change or preflight: {earlier} before {later}"
            ));
        }
    }

    violations
}

fn source_occurs_before(source: &str, earlier: &str, later: &str) -> bool {
    let Some(earlier_index) = source.find(earlier) else {
        return false;
    };
    let Some(later_index) = source.find(later) else {
        return false;
    };

    earlier_index < later_index
}

#[test]
fn repaired_cli_surface_is_rejection_only_for_removed_behavior() {
    let violations = removed_token_positive_path_violations(VERIFY_CLI_SURFACE);

    assert!(
        violations.is_empty(),
        "removed CLI tokens must stay out of positive harness paths: {violations:?}"
    );
}

#[test]
fn removed_surface_probe_rejects_generic_runtime_error_fallbacks() {
    let helper_body = removed_surface_helper_body(VERIFY_CLI_SURFACE);
    let violations = removed_surface_helper_contract_violations(VERIFY_CLI_SURFACE);

    assert!(
        violations.is_empty(),
        "removed-surface helper contract must stay hardened: {violations:?}"
    );

    assert_not_contains("scripts/verify_cli_surface.sh", helper_body, "error:");
    assert_not_contains(
        "scripts/verify_cli_surface.sh",
        helper_body,
        "unexpected argument|unrecognized subcommand|error:",
    );
    assert_all_contains(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        &[
            "local expected_parser_rejection=$2",
            "grep -F \"$expected_parser_rejection\" \"$stderr\"",
            "expect_rejected \"encrypt removed aes flag\" \"unexpected argument\"",
            "expect_rejected \"removed top level erase subcommand\" \"unrecognized subcommand\"",
        ],
    );
}

#[test]
fn removed_surface_probe_keeps_black_box_failure_diagnostics() {
    let helper_body = removed_surface_helper_body(VERIFY_CLI_SURFACE);

    assert_all_contains(
        "scripts/verify_cli_surface.sh::expect_rejected",
        helper_body,
        &[
            "stdout=\"$ROOT/rejected-$safe_name.stdout\"",
            "stderr=\"$ROOT/rejected-$safe_name.stderr\"",
            "> \"$stdout\" 2> \"$stderr\"",
            "echo \"Captured stdout: $stdout\" >&2",
            "echo \"Captured stderr: $stderr\" >&2",
            "cat \"$stderr\" >&2",
        ],
    );
    assert_occurs_before(
        "scripts/verify_cli_surface.sh::expect_rejected",
        helper_body,
        "echo \"Captured stderr: $stderr\" >&2",
        "cat \"$stderr\" >&2",
    );

    for parser_fixture_detail in [
        "clap::error::ErrorKind",
        "try_get_matches_from",
        "UnknownArgument",
        "InvalidSubcommand",
    ] {
        assert_not_contains(
            "scripts/verify_cli_surface.sh::expect_rejected",
            helper_body,
            parser_fixture_detail,
        );
    }

    assert_all_contains(
        "dexios/src/cli/tests.rs",
        DEXIOS_CLI_TESTS_RS,
        &[
            "removed_top_level_erase_subcommand_is_rejected",
            "clap::error::ErrorKind::UnknownArgument",
            "clap::error::ErrorKind::InvalidSubcommand",
        ],
    );
}

#[test]
fn source_gate_rejects_removed_token_positive_path_canary() {
    let weakened = VERIFY_CLI_SURFACE.replace(
        "expect_rejected \"encrypt removed aes flag\" \"unexpected argument\" \"$BIN\" encrypt --aes \"$dir/plain.txt\" \"$dir/plain.enc\" || return 1",
        "\"$BIN\" encrypt --aes \"$dir/plain.txt\" \"$dir/plain.enc\" # expect_rejected",
    );

    let violations = removed_token_positive_path_violations(&weakened);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("positive harness path")
                && violation.contains("--aes")),
        "source gate must reject removed tokens in positive harness paths even when a comment mentions expect_rejected: {violations:?}"
    );
}

#[test]
fn source_gate_rejects_generic_lowercase_error_fallback_canary() {
    let weakened = VERIFY_CLI_SURFACE.replace(
        "grep -F \"$expected_parser_rejection\" \"$stderr\"",
        "grep -E \"$expected_parser_rejection|error:\" \"$stderr\"",
    );

    let violations = removed_surface_helper_contract_violations(&weakened);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("generic lowercase error")),
        "source gate must reject removed-surface helpers that accept generic lowercase error text: {violations:?}"
    );
}

#[test]
fn source_gate_rejects_unanchored_relative_binary_canary() {
    let weakened = VERIFY_CLI_SURFACE.replace(
        "printf '%s/%s\\n' \"$REPO_ROOT\" \"$selected\"",
        "printf '%s\\n' \"$selected\"",
    );

    let violations = binary_selection_contract_violations(&weakened);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("repo-root-normalized relative binary")),
        "source gate must reject relative binary resolution that can become cwd-sensitive: {violations:?}"
    );
}

#[test]
fn cli_surface_harness_resolves_selected_binary_before_directory_changes() {
    let violations = binary_selection_contract_violations(VERIFY_CLI_SURFACE);

    assert!(
        violations.is_empty(),
        "binary selection contract must stay source-gated: {violations:?}"
    );

    assert_all_contains(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        &[
            "SELECTED_BIN=\"${1:-$REPO_ROOT/target/release-lto/dexios}\"",
            "resolve_selected_binary()",
            "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
            "echo \"Binary not found or not executable: $BIN\" >&2",
            "echo \"Build it first, for example: cargo build -p dexios --profile release-lto\" >&2",
            "echo \"Using binary: $BIN\"",
        ],
    );

    assert_occurs_before(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
        "if [[ ! -x \"$BIN\" ]]",
    );
    assert_occurs_before(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
        "ROOT=\"$(mktemp -d /tmp/dexios-cli-surface.XXXXXX)\"",
    );
    assert_occurs_before(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
        "cd \"$dir\"",
    );
    assert_occurs_before(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        "if [[ ! -x \"$BIN\" ]]",
        "echo \"Using binary: $BIN\"",
    );
}

#[test]
fn cli_surface_harness_preflight_names_normalized_missing_binary_before_smoke_cases() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dexios crate has repository root parent");
    let selected_binary = "./Cargo.toml.missing-dexios";
    let expected_binary = repo_root.join("Cargo.toml.missing-dexios");

    let output = Command::new("bash")
        .arg("scripts/verify_cli_surface.sh")
        .arg(selected_binary)
        .current_dir(repo_root)
        .output()
        .expect("run CLI surface harness preflight");

    let stdout = String::from_utf8(output.stdout).expect("harness stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("harness stderr is UTF-8");

    assert_eq!(
        output.status.code(),
        Some(2),
        "missing selected binary must fail during preflight: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.is_empty(),
        "missing selected binary must stop before smoke output: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Binary not found or not executable: {}",
            expected_binary.display()
        )),
        "preflight diagnostic must name the normalized selected binary: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("Build it first, for example: cargo build -p dexios --profile release-lto"),
        "preflight diagnostic must retain the build hint: stdout={stdout}\nstderr={stderr}"
    );

    for smoke_output in ["Using binary:", "Working root:", "PASS ", "FAIL "] {
        assert!(
            !stdout.contains(smoke_output) && !stderr.contains(smoke_output),
            "missing selected binary must fail before smoke cases emit {smoke_output:?}: stdout={stdout}\nstderr={stderr}"
        );
    }
}

#[test]
fn phase13_cli_output_and_decrypt_contract_is_source_gated() {
    assert_contains(
        "dexios/src/global.rs",
        DEXIOS_GLOBAL_RS,
        "eprintln!(\"[-] {}\", format!($($arg)*))",
    );
    assert_non_comment_line_count(
        "dexios/src/global.rs",
        DEXIOS_GLOBAL_RS,
        "println!(\"[-] {}\", format!($($arg)*))",
        0,
    );

    for required in [
        "generated_passphrase_secret(*i, |message| warn!(\"{message}\"))",
        "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: ",
    ] {
        assert_contains("dexios/src/global/states.rs", DEXIOS_STATES_RS, required);
    }

    for required in [
        "encrypt_auto_generated_passphrase_disclosure_uses_stderr_not_stdout",
        "--auto=4",
        "output.stderr",
        "output.stdout",
        "Your generated passphrase is intentionally shown here",
    ] {
        assert_contains(
            "dexios/tests/encrypt_cli_regressions.rs",
            DEXIOS_ENCRYPT_CLI_REGRESSION_TESTS,
            required,
        );
    }

    for required in [
        "auto.stderr",
        "auto.stdout",
        "2> \"$dir/auto.stderr\"",
        "\"$dir/auto.stderr\"",
    ] {
        assert_contains(
            "scripts/verify_cli_surface.sh",
            VERIFY_CLI_SURFACE,
            required,
        );
    }
    assert_not_contains(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        "auto_key=\"$(sed -n 's/^\\[-\\] Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: //p' \"$dir/auto.stdout\"",
    );

    for required in [
        "#[cfg(test)]\npub(crate) struct HandleRequest",
        "#[cfg(test)]\npub(crate) fn execute_handles",
        "_final_auth: V1FinalAuth",
    ] {
        assert_contains(
            "dexios-domain/src/decrypt.rs",
            DEXIOS_DOMAIN_DECRYPT_RS,
            required,
        );
    }

    let decrypt_section = normalized_rust_production_section(
        "dexios-domain/src/decrypt.rs",
        DEXIOS_DOMAIN_DECRYPT_RS,
        "fn execute_transactional_target",
        "pub(crate) fn read_v1_payload",
    );
    assert_normalized_section_order(
        "dexios-domain/src/decrypt.rs::execute_transactional_target",
        &decrypt_section,
        &[
            "StagedOutputTransaction::new",
            ".with_writer_result(",
            "decrypt_payload_with_master_key",
            "commit_after_final_auth(transaction, final_auth)",
        ],
    );

    for required in [
        "pub struct V1FinalAuth",
        "_private: ()",
        "Result<V1FinalAuth, StreamError>",
        "uncommitted scratch",
        "Ok(V1FinalAuth)",
    ] {
        assert_contains("dexios-core/src/stream.rs", DEXIOS_CORE_STREAM_RS, required);
    }
}
#[test]
fn phase22_cli_parser_baseline_and_surface_gate_are_source_gated() {
    // MGAT-02, D-04 through D-06, D-14 through D-16: parser fixtures cover the
    // clap command graph, while the script and CI gates keep the built-binary
    // smoke harness wired into maintainer and pull-request paths.

    assert_all_contains(
        "dexios/src/cli/tests.rs",
        DEXIOS_CLI_TESTS_RS,
        &[
            "cli_definition_passes_clap_debug_assertions",
            "try_get_matches_from",
            "top_level_short_flags_resolve_to_commands",
            "shared_options_parse_across_command_families",
            "auto_generation_conflicts_with_keyfiles",
            "missing_required_subcommands_are_rejected",
            "clap::error::ErrorKind::ArgumentConflict",
            "clap::error::ErrorKind::UnknownArgument",
            "clap::error::ErrorKind::InvalidSubcommand",
            "clap::error::ErrorKind::ValueValidation",
            "--auto=7",
            "keyfile-new",
        ],
    );

    assert_all_contains(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        &[
            "case_removed_token_source_gate",
            "case_removed_cli_surface_rejected",
            "expect_rejected",
            "run_case \"removed CLI surface rejected\" case_removed_cli_surface_rejected",
            "case_encrypt_decrypt_env_hash_delete_input",
            "case_encrypt_decrypt_keyfile_detached_defaults",
            "case_pack_unpack_complex_success_path",
            "\"$BIN\" header strip -f --header \"$dir/plain.hdr\" \"$dir/stripped.enc\"",
            "\"$BIN\" key change -f -k \"$dir/old.key\" -n \"$dir/changed.key\" \"$dir/change.enc\"",
        ],
    );

    assert_occurs_before(
        ".github/workflows/cli-surface.yml",
        CLI_SURFACE_WORKFLOW,
        "run: cargo build --locked -p dexios --profile release-lto",
        "bash scripts/verify_cli_surface.sh",
    );
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run bash scripts/verify_cli_surface.sh",
        1,
    );
}

// --- Phase 23 gate tests ---
#[test]
fn phase23_cli_command_split_is_source_gated() {
    // CLID-01/CLID-02, D-01 through D-15: command builders and shared option
    // helpers stay in focused parser modules while build_cli remains the
    // ordered assembly point without retaining the old oversized-builder lint
    // allowance.

    assert_all_contains(
        "dexios/src/cli/commands/stream.rs",
        DEXIOS_CLI_COMMANDS_STREAM_RS,
        &[
            "fn encrypt_command() -> Command",
            "fn decrypt_command() -> Command",
            "Command::new(\"encrypt\")",
            "Command::new(\"decrypt\")",
            "args::delete_input_arg",
            "args::autogenerate_arg",
        ],
    );
    assert_all_contains(
        "dexios/src/cli/commands/archive.rs",
        DEXIOS_CLI_COMMANDS_ARCHIVE_RS,
        &[
            "fn pack_command() -> Command",
            "fn unpack_command() -> Command",
            "Command::new(\"pack\")",
            "Command::new(\"unpack\")",
            ".num_args(1..)",
            "args::delete_source_arg",
            "args::delete_input_arg",
        ],
    );
    assert_all_contains(
        "dexios/src/cli/commands/hash.rs",
        DEXIOS_CLI_COMMANDS_HASH_RS,
        &[
            "fn hash_command() -> Command",
            "Command::new(\"hash\")",
            ".num_args(1..)",
        ],
    );
    assert_all_contains(
        "dexios/src/cli/args.rs",
        DEXIOS_CLI_ARGS_RS,
        &[
            "autogenerate_arg",
            "detached_header_output_arg",
            "detached_header_input_arg",
            "keyfile_old_arg",
            "keyfile_new_arg",
        ],
    );
    assert_all_contains(
        "dexios/src/cli/commands/key.rs",
        DEXIOS_CLI_COMMANDS_KEY_RS,
        &[
            "fn key_command() -> Command",
            "Command::new(\"key\")",
            "Command::new(\"change\")",
            "Command::new(\"add\")",
            "Command::new(\"del\")",
            "Command::new(\"verify\")",
            "conflicts_with(\"keyfile-new\")",
        ],
    );
    assert_all_contains(
        "dexios/src/cli/commands/header.rs",
        DEXIOS_CLI_COMMANDS_HEADER_RS,
        &[
            "fn header_command() -> Command",
            "Command::new(\"header\")",
            "Command::new(\"dump\")",
            "Command::new(\"restore\")",
            "Command::new(\"strip\")",
            "Command::new(\"details\")",
        ],
    );
    assert_all_contains(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        &[
            "mod commands;",
            "commands::stream::encrypt_command()",
            "commands::stream::decrypt_command()",
            "commands::hash::hash_command()",
            "commands::archive::pack_command()",
            "commands::archive::unpack_command()",
            "commands::key::key_command()",
            "commands::header::header_command()",
        ],
    );
    assert_not_contains(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "#[allow(clippy::too_many_lines)]",
    );

    assert_occurs_before(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "commands::stream::encrypt_command()",
        "commands::stream::decrypt_command()",
    );
    assert_occurs_before(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "commands::stream::decrypt_command()",
        "commands::hash::hash_command()",
    );
    assert_occurs_before(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "commands::hash::hash_command()",
        "commands::archive::pack_command()",
    );
    assert_occurs_before(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "commands::archive::pack_command()",
        "commands::archive::unpack_command()",
    );
    assert_occurs_before(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "commands::archive::unpack_command()",
        "commands::key::key_command()",
    );
    assert_occurs_before(
        "dexios/src/cli.rs",
        DEXIOS_CLI_RS,
        "commands::key::key_command()",
        "commands::header::header_command()",
    );

    for moved_builder in [
        "Command::new(\"encrypt\")",
        "Command::new(\"decrypt\")",
        "Command::new(\"hash\")",
        "Command::new(\"pack\")",
        "Command::new(\"unpack\")",
        "Command::new(\"key\")",
        "Command::new(\"header\")",
    ] {
        assert_not_contains("dexios/src/cli.rs", DEXIOS_CLI_RS, moved_builder);
        assert_not_contains(
            "dexios/src/subcommands.rs",
            DEXIOS_SUBCOMMANDS_RS,
            moved_builder,
        );
    }

    assert_all_contains(
        "dexios/src/cli/tests.rs",
        DEXIOS_CLI_TESTS_RS,
        &[
            "top_level_command_registration_order_is_stable",
            ".get_subcommands()",
            "\"encrypt\", \"decrypt\", \"hash\", \"pack\", \"unpack\", \"key\", \"header\"",
        ],
    );
}

// --- Phase 24 gate tests ---
#[test]
fn phase24_cli_routing_and_parameter_extraction_are_source_gated() {
    // CLIR-01/CLIR-02/PARM-01, D-01 through D-16: routing stays adapter-local
    // and fallible, nested header/key adapters receive leaf matches, and
    // parameter extraction errors remain explicit instead of silently falling
    // through to success or key-source fallback.

    assert_all_contains(
        "dexios/src/main.rs",
        DEXIOS_MAIN_RS,
        &[
            "CliRoute::from_matches(&matches)?.dispatch()",
            "enum CliRoute<'a>",
            "enum HeaderRoute<'a>",
            "enum KeyRoute<'a>",
            "HeaderRoute::from_matches(sub_matches)?",
            "KeyRoute::from_matches(sub_matches)?",
            "internal CLI adapter error",
        ],
    );
    assert_not_contains("dexios/src/main.rs", DEXIOS_MAIN_RS, "_ => (),");

    for nested_unwrap in [
        "subcommand_matches(\"dump\").unwrap()",
        "subcommand_matches(\"restore\").unwrap()",
        "subcommand_matches(\"strip\").unwrap()",
        "subcommand_matches(\"details\").unwrap()",
        "subcommand_matches(\"change\").unwrap()",
        "subcommand_matches(\"add\").unwrap()",
        "subcommand_matches(\"del\").unwrap()",
        "subcommand_matches(\"verify\").unwrap()",
    ] {
        assert_not_contains(
            "dexios/src/subcommands.rs",
            DEXIOS_SUBCOMMANDS_RS,
            nested_unwrap,
        );
    }

    assert_all_contains(
        "dexios/src/global/parameters.rs",
        DEXIOS_PARAMETERS_RS,
        &[
            "pub(crate) fn get_optional_param",
            "try_get_one::<String>(name)",
            "try_get_many::<String>(name)",
            "internal CLI adapter error: required argument",
            "internal CLI adapter error: required repeated argument",
            "internal CLI adapter error: optional argument",
            "get_optional_param(\"header\", sub_matches)?",
            "required_parameter_missing_returns_internal_adapter_error",
            "repeated_parameter_missing_returns_internal_adapter_error",
            "optional_parameter_absent_returns_none",
            "optional_parameter_present_returns_borrowed_value",
            "optional_parameter_mismatched_access_returns_internal_adapter_error",
        ],
    );

    assert_all_contains(
        "dexios/src/global/states.rs",
        DEXIOS_STATES_RS,
        &[
            "get_optional_param(keyfile_descriptor, sub_matches)?",
            "get_optional_param(\"autogenerate\", sub_matches)?",
            "key_source_true_absence_preserves_user_fallback",
            "key_source_unreadable_keyfile_returns_adapter_error_before_fallback",
            "key_source_unreadable_autogenerate_returns_adapter_error_before_fallback",
        ],
    );
    assert_not_contains(
        "dexios/src/global/states.rs",
        DEXIOS_STATES_RS,
        ".try_get_one::<String>(keyfile_descriptor)\n            .ok()\n            .flatten()",
    );
    assert_not_contains(
        "dexios/src/global/states.rs",
        DEXIOS_STATES_RS,
        ".try_get_one::<String>(\"autogenerate\")\n            .ok()\n            .flatten()",
    );
}
