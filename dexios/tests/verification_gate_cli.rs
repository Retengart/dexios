#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
mod verification_gate_support;

use verification_gate_support::*;

#[test]
fn repaired_cli_surface_is_rejection_only_for_removed_behavior() {
    for (line_number, line) in VERIFY_CLI_SURFACE.lines().enumerate() {
        if !is_non_comment_line(line) {
            continue;
        }

        let has_removed_flag = line.contains("--aes")
            || line.contains("--argon")
            || line.contains("--zstd")
            || line.contains("--erase");
        let has_removed_subcommand = line.contains("\"$BIN\" erase");

        if has_removed_flag || has_removed_subcommand {
            assert!(
                line.contains("expect_rejected"),
                "scripts/verify_cli_surface.sh:{} removed CLI token must stay in an expect_rejected context: {}",
                line_number + 1,
                line
            );
        }
    }
}

#[test]
fn cli_surface_harness_resolves_selected_binary_before_directory_changes() {
    assert_all_contains(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        &[
            "SELECTED_BIN=\"${1:-$REPO_ROOT/target/release-lto/dexios}\"",
            "resolve_selected_binary()",
            "BIN=\"$(resolve_selected_binary \"$SELECTED_BIN\")\"",
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
        ],
    );

    assert_occurs_before(
        ".github/workflows/cli-surface.yml",
        CLI_SURFACE_WORKFLOW,
        "run: cargo build -p dexios --profile release-lto",
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
