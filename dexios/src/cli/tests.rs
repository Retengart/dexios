const CLI_ARGS_RS: &str = include_str!("args.rs");
const CLI_RS: &str = include_str!("../cli.rs");
const CLI_STREAM_COMMANDS_RS: &str = include_str!("commands/stream.rs");
const CLI_ARCHIVE_COMMANDS_RS: &str = include_str!("commands/archive.rs");
const CLI_HASH_COMMANDS_RS: &str = include_str!("commands/hash.rs");
const CLI_KEY_COMMANDS_RS: &str = include_str!("commands/key.rs");
const CLI_HEADER_COMMANDS_RS: &str = include_str!("commands/header.rs");

fn parse_ok<const N: usize>(args: [&str; N]) -> clap::ArgMatches {
    super::build_cli()
        .try_get_matches_from(args)
        .expect("CLI should parse")
}

fn assert_parser_error<const N: usize>(
    args: [&str; N],
    expected_kind: clap::error::ErrorKind,
    expected_text: &str,
) {
    let error = super::build_cli()
        .try_get_matches_from(args)
        .expect_err("CLI input should be rejected");

    assert_eq!(error.kind(), expected_kind);
    assert!(
        error.to_string().contains(expected_text),
        "error should contain {expected_text}: {error}"
    );
}

fn assert_file_pair_command<const N: usize>(
    args: [&str; N],
    command: &str,
    input: &str,
    output: &str,
) {
    let matches = parse_ok(args);
    let (name, sub) = matches.subcommand().expect("subcommand");

    assert_eq!(name, command);
    assert_eq!(
        sub.get_one::<String>("input").map(String::as_str),
        Some(input)
    );
    assert_eq!(
        sub.get_one::<String>("output").map(String::as_str),
        Some(output)
    );
}

fn assert_unknown_argument_is_rejected<const N: usize>(args: [&str; N], rejected: &str) {
    let error = super::build_cli()
        .try_get_matches_from(args)
        .expect_err("removed CLI argument should be rejected");

    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    assert!(
        error.to_string().contains(rejected),
        "error should name the rejected argument {rejected}: {error}"
    );
}

fn assert_argon_is_rejected<const N: usize>(args: [&str; N]) {
    assert_unknown_argument_is_rejected(args, "--argon");
}

fn assert_invalid_auto_value_is_rejected<const N: usize>(args: [&str; N]) {
    let error = super::build_cli()
        .try_get_matches_from(args)
        .expect_err("invalid generated-passphrase count should be rejected");

    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    assert!(
        error
            .to_string()
            .contains("generated passphrase word count"),
        "error should name the generated passphrase count: {error}"
    );
    assert!(
        !error
            .to_string()
            .contains("Your generated passphrase is intentionally shown here"),
        "parser error must not disclose a generated passphrase: {error}"
    );
}

#[test]
fn cli_definition_passes_clap_debug_assertions() {
    super::build_cli().debug_assert();
}

#[test]
fn top_level_command_registration_order_is_stable() {
    let cli = super::build_cli();
    let command_names = cli
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();

    assert_eq!(
        command_names.as_slice(),
        [
            "encrypt", "decrypt", "hash", "pack", "unpack", "key", "header"
        ]
    );
}

#[test]
fn shared_arg_factories_are_source_gated() {
    for required in [
        "input_arg",
        "output_arg",
        "keyfile_arg",
        "force_arg",
        "hash_arg",
        "delete_input_arg",
        "delete_source_arg",
        "verbose_arg",
        "recursive_arg",
        "detached_header_output_arg",
        "detached_header_input_arg",
        "keyfile_old_arg",
        "keyfile_new_arg",
        "autogenerate_arg",
        "super::validate_autogenerate_words",
        "conflicts_with(conflict_target)",
    ] {
        assert!(
            CLI_ARGS_RS.contains(required),
            "dexios/src/cli/args.rs must contain {required:?}"
        );
    }
}

#[test]
fn top_level_command_builders_are_split_by_family() {
    assert!(CLI_STREAM_COMMANDS_RS.contains("fn encrypt_command() -> Command"));
    assert!(CLI_STREAM_COMMANDS_RS.contains("fn decrypt_command() -> Command"));
    assert!(CLI_ARCHIVE_COMMANDS_RS.contains("fn pack_command() -> Command"));
    assert!(CLI_ARCHIVE_COMMANDS_RS.contains("fn unpack_command() -> Command"));
    assert!(CLI_HASH_COMMANDS_RS.contains("fn hash_command() -> Command"));

    for ordered_call in [
        "commands::stream::encrypt_command()",
        "commands::stream::decrypt_command()",
        "commands::hash::hash_command()",
        "commands::archive::pack_command()",
        "commands::archive::unpack_command()",
    ] {
        assert!(
            CLI_RS.contains(ordered_call),
            "build_cli() must assemble top-level commands through {ordered_call}"
        );
    }
}

#[test]
fn nested_command_builders_are_split_by_family() {
    assert!(CLI_KEY_COMMANDS_RS.contains("fn key_command() -> Command"));
    for required in [
        "Command::new(\"key\")",
        "Command::new(\"change\")",
        "Command::new(\"add\")",
        "Command::new(\"del\")",
        "Command::new(\"verify\")",
        "args::keyfile_old_arg()",
        "args::keyfile_new_arg()",
        "args::keyfile_arg()",
        "conflicts_with(\"keyfile-new\")",
    ] {
        assert!(
            CLI_KEY_COMMANDS_RS.contains(required),
            "dexios/src/cli/commands/key.rs must contain {required:?}"
        );
    }

    assert!(CLI_HEADER_COMMANDS_RS.contains("fn header_command() -> Command"));
    for required in [
        "Command::new(\"header\")",
        "Command::new(\"dump\")",
        "Command::new(\"restore\")",
        "Command::new(\"strip\")",
        "Command::new(\"details\")",
        "args::force_arg()",
    ] {
        assert!(
            CLI_HEADER_COMMANDS_RS.contains(required),
            "dexios/src/cli/commands/header.rs must contain {required:?}"
        );
    }

    for ordered_call in [
        "commands::key::key_command()",
        "commands::header::header_command()",
    ] {
        assert!(
            CLI_RS.contains(ordered_call),
            "build_cli() must assemble nested commands through {ordered_call}"
        );
    }

    for moved_builder in ["Command::new(\"key\")", "Command::new(\"header\")"] {
        assert!(
            !CLI_RS.contains(moved_builder),
            "build_cli() should not inline nested builder {moved_builder:?}"
        );
    }
}

#[test]
fn encrypt_help_does_not_panic_from_duplicate_args() {
    let result = std::panic::catch_unwind(|| {
        let _ = super::build_cli().try_get_matches_from(["dexios", "encrypt", "--help"]);
    });

    assert!(result.is_ok(), "encrypt --help should not panic");
}

#[test]
fn encrypt_command_accepts_header_and_auto() {
    let matches = parse_ok([
        "dexios", "encrypt", "--header", "file.hdr", "--auto=7", "in.bin", "out.enc",
    ]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "encrypt");
    assert_eq!(
        sub.get_one::<String>("input").map(String::as_str),
        Some("in.bin")
    );
    assert_eq!(
        sub.get_one::<String>("output").map(String::as_str),
        Some("out.enc")
    );
    assert_eq!(
        sub.get_one::<String>("header").map(String::as_str),
        Some("file.hdr")
    );
    assert_eq!(
        sub.get_one::<String>("autogenerate").map(String::as_str),
        Some("7")
    );
}

#[test]
fn encrypt_auto_without_value_defaults_to_seven_words() {
    let matches = parse_ok(["dexios", "encrypt", "--auto", "in.bin", "out.enc"]);
    let (_, sub) = matches.subcommand().expect("subcommand");

    assert_eq!(
        sub.get_one::<String>("autogenerate").map(String::as_str),
        Some("7")
    );
}

#[test]
fn encrypt_auto_rejects_invalid_explicit_values() {
    for auto in ["--auto=0", "--auto=-1", "--auto=abc"] {
        assert_invalid_auto_value_is_rejected(["dexios", "encrypt", auto, "in.bin", "out.enc"]);
    }
}

#[test]
fn removed_argon_flag_is_rejected_for_encrypt() {
    assert_argon_is_rejected(["dexios", "encrypt", "--argon", "in.bin", "out.enc"]);
}

#[test]
fn removed_argon_flag_is_rejected_for_pack() {
    assert_argon_is_rejected(["dexios", "pack", "--argon", "dir-a", "archive.dex"]);
}

#[test]
fn removed_aes_flag_is_rejected_for_encrypt() {
    assert_unknown_argument_is_rejected(
        ["dexios", "encrypt", "--aes", "in.bin", "out.enc"],
        "--aes",
    );
}

#[test]
fn removed_aes_flag_is_rejected_for_pack() {
    assert_unknown_argument_is_rejected(
        ["dexios", "pack", "--aes", "dir-a", "archive.dex"],
        "--aes",
    );
}

#[test]
fn removed_erase_flag_is_rejected_for_encrypt() {
    assert_unknown_argument_is_rejected(
        ["dexios", "encrypt", "--erase", "in.bin", "out.enc"],
        "--erase",
    );
}

#[test]
fn removed_erase_flag_is_rejected_for_decrypt() {
    assert_unknown_argument_is_rejected(
        ["dexios", "decrypt", "--erase", "in.enc", "out.bin"],
        "--erase",
    );
}

#[test]
fn removed_erase_flag_is_rejected_for_pack() {
    assert_unknown_argument_is_rejected(
        ["dexios", "pack", "--erase", "dir-a", "archive.dex"],
        "--erase",
    );
}

#[test]
fn removed_erase_flag_is_rejected_for_unpack() {
    assert_unknown_argument_is_rejected(
        ["dexios", "unpack", "--erase", "archive.dex", "out"],
        "--erase",
    );
}

#[test]
fn removed_top_level_erase_subcommand_is_rejected() {
    let error = super::build_cli()
        .try_get_matches_from(["dexios", "erase", "file.txt"])
        .expect_err("top-level erase workflow should stay removed");

    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    assert!(
        error.to_string().contains("erase"),
        "error should name the removed subcommand: {error}"
    );
}

#[test]
fn hash_command_accepts_multiple_inputs() {
    let matches = parse_ok(["dexios", "hash", "one.bin", "two.bin"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "hash");
    let values = sub
        .get_many::<String>("input")
        .expect("multiple input files")
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(values, ["one.bin", "two.bin"]);
}

#[test]
fn pack_command_accepts_multiple_paths_without_compression_selector() {
    let matches = parse_ok(["dexios", "pack", "dir-a", "dir-b", "archive.dex"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "pack");
    let values = sub
        .get_many::<String>("input")
        .expect("multiple input paths")
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(values, ["dir-a", "dir-b"]);
    assert_eq!(
        sub.get_one::<String>("output").map(String::as_str),
        Some("archive.dex")
    );
}

#[test]
fn pack_auto_without_value_defaults_to_seven_words() {
    let matches = parse_ok(["dexios", "pack", "--auto", "dir-a", "archive.dex"]);
    let (_, sub) = matches.subcommand().expect("subcommand");

    assert_eq!(
        sub.get_one::<String>("autogenerate").map(String::as_str),
        Some("7")
    );
}

#[test]
fn pack_auto_rejects_invalid_explicit_values() {
    for auto in ["--auto=0", "--auto=-1", "--auto=abc"] {
        assert_invalid_auto_value_is_rejected(["dexios", "pack", auto, "dir-a", "archive.dex"]);
    }
}

#[test]
fn current_delete_after_success_flags_parse() {
    let encrypt = parse_ok(["dexios", "encrypt", "--delete-input", "in.bin", "out.enc"]);
    let (_, encrypt) = encrypt.subcommand().expect("encrypt subcommand");
    assert!(encrypt.get_flag("delete-input"));

    let decrypt = parse_ok(["dexios", "decrypt", "--delete-input", "in.enc", "out.bin"]);
    let (_, decrypt) = decrypt.subcommand().expect("decrypt subcommand");
    assert!(decrypt.get_flag("delete-input"));

    let pack = parse_ok(["dexios", "pack", "--delete-source", "dir-a", "archive.dex"]);
    let (_, pack) = pack.subcommand().expect("pack subcommand");
    assert!(pack.get_flag("delete-source"));

    let unpack = parse_ok(["dexios", "unpack", "--delete-input", "archive.dex", "out"]);
    let (_, unpack) = unpack.subcommand().expect("unpack subcommand");
    assert!(unpack.get_flag("delete-input"));
}

#[test]
fn removed_zstd_flag_is_rejected_for_pack() {
    let error = super::build_cli()
        .try_get_matches_from(["dexios", "pack", "--zstd", "dir-a", "archive.dex"])
        .expect_err("--zstd should not be a public pack compression selector");

    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    assert!(
        error.to_string().contains("--zstd"),
        "error should name the removed flag: {error}"
    );
}

#[test]
fn key_add_command_accepts_old_and_new_keyfiles() {
    let matches = parse_ok([
        "dexios",
        "key",
        "add",
        "-k",
        "old.key",
        "-n",
        "new.key",
        "cipher.enc",
    ]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "key");
    let add = sub.subcommand_matches("add").expect("key add");
    assert_eq!(
        add.get_one::<String>("keyfile-old").map(String::as_str),
        Some("old.key")
    );
    assert_eq!(
        add.get_one::<String>("keyfile-new").map(String::as_str),
        Some("new.key")
    );
    assert_eq!(
        add.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
}

#[test]
fn key_add_auto_without_value_defaults_to_seven_words() {
    let matches = parse_ok(["dexios", "key", "add", "--auto", "cipher.enc"]);
    let (_, sub) = matches.subcommand().expect("subcommand");
    let add = sub.subcommand_matches("add").expect("key add");

    assert_eq!(
        add.get_one::<String>("autogenerate").map(String::as_str),
        Some("7")
    );
}

#[test]
fn key_add_auto_rejects_invalid_explicit_values() {
    for auto in ["--auto=0", "--auto=-1", "--auto=abc"] {
        assert_invalid_auto_value_is_rejected(["dexios", "key", "add", auto, "cipher.enc"]);
    }
}

#[test]
fn key_change_command_accepts_old_and_new_keyfiles() {
    let matches = parse_ok([
        "dexios",
        "key",
        "change",
        "-k",
        "old.key",
        "-n",
        "new.key",
        "cipher.enc",
    ]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "key");
    let change = sub.subcommand_matches("change").expect("key change");
    assert_eq!(
        change.get_one::<String>("keyfile-old").map(String::as_str),
        Some("old.key")
    );
    assert_eq!(
        change.get_one::<String>("keyfile-new").map(String::as_str),
        Some("new.key")
    );
    assert_eq!(
        change.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
}

#[test]
fn key_change_auto_without_value_defaults_to_seven_words() {
    let matches = parse_ok(["dexios", "key", "change", "--auto", "cipher.enc"]);
    let (_, sub) = matches.subcommand().expect("subcommand");
    let change = sub.subcommand_matches("change").expect("key change");

    assert_eq!(
        change.get_one::<String>("autogenerate").map(String::as_str),
        Some("7")
    );
}

#[test]
fn key_change_auto_rejects_invalid_explicit_values() {
    for auto in ["--auto=0", "--auto=-1", "--auto=abc"] {
        assert_invalid_auto_value_is_rejected(["dexios", "key", "change", auto, "cipher.enc"]);
    }
}

#[test]
fn removed_argon_flag_is_rejected_for_key_add() {
    assert_argon_is_rejected(["dexios", "key", "add", "--argon", "cipher.enc"]);
}

#[test]
fn removed_argon_flag_is_rejected_for_key_change() {
    assert_argon_is_rejected(["dexios", "key", "change", "--argon", "cipher.enc"]);
}

#[test]
fn key_del_command_accepts_input_and_keyfile() {
    let matches = parse_ok(["dexios", "key", "del", "-k", "keyfile.bin", "cipher.enc"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "key");
    let del = sub.subcommand_matches("del").expect("key del");
    assert_eq!(
        del.get_one::<String>("keyfile").map(String::as_str),
        Some("keyfile.bin")
    );
    assert_eq!(
        del.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
}

#[test]
fn key_verify_command_accepts_input_and_keyfile() {
    let matches = parse_ok(["dexios", "key", "verify", "-k", "keyfile.bin", "cipher.enc"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "key");
    let verify = sub.subcommand_matches("verify").expect("key verify");
    assert_eq!(
        verify.get_one::<String>("keyfile").map(String::as_str),
        Some("keyfile.bin")
    );
    assert_eq!(
        verify.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
}

#[test]
fn header_dump_command_accepts_input_output_and_force() {
    let matches = parse_ok(["dexios", "header", "dump", "-f", "cipher.enc", "dump.hdr"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "header");
    let dump = sub.subcommand_matches("dump").expect("header dump");
    assert!(dump.get_flag("force"));
    assert_eq!(
        dump.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
    assert_eq!(
        dump.get_one::<String>("output").map(String::as_str),
        Some("dump.hdr")
    );
}

#[test]
fn header_restore_command_accepts_input_and_output() {
    let matches = parse_ok([
        "dexios",
        "header",
        "restore",
        "--force",
        "dump.hdr",
        "cipher.enc",
    ]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "header");
    let restore = sub.subcommand_matches("restore").expect("header restore");
    assert_eq!(
        restore.get_one::<String>("input").map(String::as_str),
        Some("dump.hdr")
    );
    assert_eq!(
        restore.get_one::<String>("output").map(String::as_str),
        Some("cipher.enc")
    );
    assert!(restore.get_flag("force"));
}

#[test]
fn header_strip_command_accepts_input() {
    let matches = parse_ok(["dexios", "header", "strip", "--force", "cipher.enc"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "header");
    let strip = sub.subcommand_matches("strip").expect("header strip");
    assert_eq!(
        strip.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
    assert!(strip.get_flag("force"));
}

#[test]
fn header_details_command_accepts_input() {
    let matches = parse_ok(["dexios", "header", "details", "cipher.enc"]);

    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "header");
    let details = sub.subcommand_matches("details").expect("header details");
    assert_eq!(
        details.get_one::<String>("input").map(String::as_str),
        Some("cipher.enc")
    );
}

#[test]
fn top_level_short_flags_resolve_to_commands() {
    assert_file_pair_command(
        ["dexios", "-e", "in.bin", "out.enc"],
        "encrypt",
        "in.bin",
        "out.enc",
    );
    assert_file_pair_command(
        ["dexios", "-d", "in.enc", "out.bin"],
        "decrypt",
        "in.enc",
        "out.bin",
    );
    assert_file_pair_command(
        ["dexios", "-u", "archive.dex", "out"],
        "unpack",
        "archive.dex",
        "out",
    );

    let matches = parse_ok(["dexios", "-p", "dir-a", "archive.dex"]);
    let (name, sub) = matches.subcommand().expect("subcommand");
    assert_eq!(name, "pack");
    let values = sub
        .get_many::<String>("input")
        .expect("input paths")
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(values, ["dir-a"]);
    assert_eq!(
        sub.get_one::<String>("output").map(String::as_str),
        Some("archive.dex")
    );
}

#[test]
fn shared_options_parse_across_command_families() {
    let encrypt = parse_ok([
        "dexios",
        "encrypt",
        "-k",
        "key.bin",
        "--header",
        "file.hdr",
        "-f",
        "-H",
        "--delete-input",
        "in.bin",
        "out.enc",
    ]);
    let (_, encrypt) = encrypt.subcommand().expect("encrypt subcommand");
    assert_eq!(
        encrypt.get_one::<String>("keyfile").map(String::as_str),
        Some("key.bin")
    );
    assert_eq!(
        encrypt.get_one::<String>("header").map(String::as_str),
        Some("file.hdr")
    );
    assert!(encrypt.get_flag("force"));
    assert!(encrypt.get_flag("hash"));
    assert!(encrypt.get_flag("delete-input"));

    let decrypt = parse_ok([
        "dexios",
        "decrypt",
        "-k",
        "key.bin",
        "--header",
        "file.hdr",
        "-f",
        "-H",
        "--delete-input",
        "in.enc",
        "out.bin",
    ]);
    let (_, decrypt) = decrypt.subcommand().expect("decrypt subcommand");
    assert_eq!(
        decrypt.get_one::<String>("keyfile").map(String::as_str),
        Some("key.bin")
    );
    assert_eq!(
        decrypt.get_one::<String>("header").map(String::as_str),
        Some("file.hdr")
    );
    assert!(decrypt.get_flag("force"));
    assert!(decrypt.get_flag("hash"));
    assert!(decrypt.get_flag("delete-input"));

    let pack = parse_ok([
        "dexios",
        "pack",
        "-k",
        "key.bin",
        "--header",
        "pack.hdr",
        "-f",
        "-H",
        "--delete-source",
        "-v",
        "-r",
        "dir-a",
        "dir-b",
        "archive.dex",
    ]);
    let (_, pack) = pack.subcommand().expect("pack subcommand");
    let inputs = pack
        .get_many::<String>("input")
        .expect("input paths")
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(inputs, ["dir-a", "dir-b"]);
    assert_eq!(
        pack.get_one::<String>("output").map(String::as_str),
        Some("archive.dex")
    );
    assert_eq!(
        pack.get_one::<String>("keyfile").map(String::as_str),
        Some("key.bin")
    );
    assert_eq!(
        pack.get_one::<String>("header").map(String::as_str),
        Some("pack.hdr")
    );
    assert!(pack.get_flag("force"));
    assert!(pack.get_flag("hash"));
    assert!(pack.get_flag("delete-source"));
    assert!(pack.get_flag("verbose"));
    assert!(pack.get_flag("recursive"));

    let unpack = parse_ok([
        "dexios",
        "unpack",
        "-k",
        "key.bin",
        "--header",
        "pack.hdr",
        "-f",
        "-H",
        "--delete-input",
        "-v",
        "archive.dex",
        "out",
    ]);
    let (_, unpack) = unpack.subcommand().expect("unpack subcommand");
    assert_eq!(
        unpack.get_one::<String>("keyfile").map(String::as_str),
        Some("key.bin")
    );
    assert_eq!(
        unpack.get_one::<String>("header").map(String::as_str),
        Some("pack.hdr")
    );
    assert!(unpack.get_flag("force"));
    assert!(unpack.get_flag("hash"));
    assert!(unpack.get_flag("delete-input"));
    assert!(unpack.get_flag("verbose"));
}

#[test]
fn auto_generation_conflicts_with_keyfiles() {
    assert_parser_error(
        [
            "dexios", "encrypt", "--auto=7", "-k", "key.bin", "in.bin", "out.enc",
        ],
        clap::error::ErrorKind::ArgumentConflict,
        "keyfile",
    );
    assert_parser_error(
        [
            "dexios",
            "pack",
            "--auto=7",
            "-k",
            "key.bin",
            "dir-a",
            "archive.dex",
        ],
        clap::error::ErrorKind::ArgumentConflict,
        "keyfile",
    );
    assert_parser_error(
        [
            "dexios",
            "key",
            "add",
            "--auto=7",
            "-n",
            "new.key",
            "cipher.enc",
        ],
        clap::error::ErrorKind::ArgumentConflict,
        "keyfile-new",
    );
    assert_parser_error(
        [
            "dexios",
            "key",
            "change",
            "--auto=7",
            "-n",
            "new.key",
            "cipher.enc",
        ],
        clap::error::ErrorKind::ArgumentConflict,
        "keyfile-new",
    );
}

#[test]
fn missing_required_subcommands_are_rejected() {
    let top_level = super::build_cli()
        .try_get_matches_from(["dexios"])
        .expect_err("top-level command should be required");
    assert_missing_command_shape(top_level);

    for args in [["dexios", "key"], ["dexios", "header"]] {
        let error = super::build_cli()
            .try_get_matches_from(args)
            .expect_err("missing command shape should be rejected by clap");
        assert_missing_command_shape(error);
    }
}

fn assert_missing_command_shape(error: clap::Error) {
    let kind = format!("{:?}", error.kind());

    assert!(
        kind.contains("DisplayHelp") || kind.contains("Missing"),
        "unexpected error kind: {kind} ({error})"
    );
}
