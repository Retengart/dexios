use clap::{Arg, ArgAction, Command};
use core::key::PassphraseWordCount;

pub mod prompt;

fn validate_autogenerate_words(words: &str) -> Result<String, String> {
    let parsed = words
        .parse::<u16>()
        .map_err(|_| "generated passphrase word count must be a positive integer".to_owned())?;
    PassphraseWordCount::try_new(parsed)
        .map_err(|_| "generated passphrase word count must be a positive integer".to_owned())?;
    Ok(words.to_owned())
}

// this defines all of the clap subcommands and arguments
// it's long, and clunky, but i feel that's just the nature of the clap builder api
// it returns the ArgMatches so that a match statement can send everything to the correct place
#[allow(clippy::too_many_lines)]
pub fn build_cli() -> Command {
    let encrypt = Command::new("encrypt")
        .short_flag('e')
        .about("Encrypt a file")
        .arg(
            Arg::new("input")
                .value_name("input")
                .action(ArgAction::Set)
                .required(true)
                .help("The file to encrypt"),
        )
        .arg(
            Arg::new("output")
                .value_name("output")
                .action(ArgAction::Set)
                .required(true)
                .help("The output file"),
        )
        .arg(
            Arg::new("keyfile")
                .short('k')
                .long("keyfile")
                .value_name("file")
                .action(ArgAction::Set)
                .help("Use a keyfile instead of a password"),
        )
        .arg(
            Arg::new("delete-input")
                .long("delete-input")
                .action(ArgAction::SetTrue)
                .help("Delete the input file after a successful encrypt"),
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .action(ArgAction::SetTrue)
                .help("Return a BLAKE3 hash of the encrypted file"),
        )
        .arg(
            Arg::new("autogenerate")
                .long("auto")
                .value_name("# of words")
                .num_args(0..=1)
                .default_missing_value("7")
                .value_parser(validate_autogenerate_words)
                .action(ArgAction::Set)
                .require_equals(true)
                .help("Autogenerate a passphrase (default is 7 words)")
                .conflicts_with("keyfile"),
        )
        .arg(
            Arg::new("header")
                .long("header")
                .value_name("file")
                .action(ArgAction::Set)
                .help("Store the header separately from the file"),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Force all actions"),
        );

    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt a file")
        .arg(
            Arg::new("input")
                .value_name("input")
                .action(ArgAction::Set)
                .required(true)
                .help("The file to decrypt"),
        )
        .arg(
            Arg::new("output")
                .value_name("output")
                .action(ArgAction::Set)
                .required(true)
                .help("The output file"),
        )
        .arg(
            Arg::new("keyfile")
                .short('k')
                .long("keyfile")
                .value_name("file")
                .action(ArgAction::Set)
                .help("Use a keyfile instead of a password"),
        )
        .arg(
            Arg::new("header")
                .long("header")
                .value_name("file")
                .action(ArgAction::Set)
                .help("Use a header file that was dumped"),
        )
        .arg(
            Arg::new("delete-input")
                .long("delete-input")
                .action(ArgAction::SetTrue)
                .help("Delete the input file after a successful decrypt"),
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .action(ArgAction::SetTrue)
                .help("Return a BLAKE3 hash of the encrypted file"),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Force all actions"),
        );

    Command::new("dexios")
        .version(clap::crate_version!())
        .author(clap::crate_authors!("\n"))
        .about("Secure, fast and modern command-line encryption of files.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(encrypt.clone())
        .subcommand(decrypt.clone())
        .subcommand(
            Command::new("hash").about("Hash files with BLAKE3").arg(
                Arg::new("input")
                    .value_name("input")
                    .action(ArgAction::Set)
                    .required(true)
                    .help("The file(s) to hash")
                    .num_args(1..),
            ),
        )
        .subcommand(
            Command::new("pack")
            .about("Pack and encrypt an entire directory")
            .short_flag('p')
            .arg(
                Arg::new("input")
                    .value_name("input")
                    .action(ArgAction::Set)
                    .num_args(1..)
                    .required(true)
                    .help("The directory to encrypt"),
            )
            .arg(
                Arg::new("output")
                    .value_name("output")
                    .action(ArgAction::Set)
                    .required(true)
                    .help("The output file"),
            )
            .arg(
                Arg::new("delete-source")
                    .long("delete-source")
                    .action(ArgAction::SetTrue)
                    .help("Delete the source directories after a successful pack")
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .action(ArgAction::SetTrue)
                    .help("Show a detailed output"),
            )
            .arg(
                Arg::new("autogenerate")
                    .long("auto")
                    .value_name("# of words")
                    .num_args(0..=1)
                    .default_missing_value("7")
                    .value_parser(validate_autogenerate_words)
                    .action(ArgAction::Set)
                    .require_equals(true)
                    .help("Autogenerate a passphrase (default is 7 words)")
                    .conflicts_with("keyfile"),
            )
            .arg(
                Arg::new("header")
                    .long("header")
                    .value_name("file")
                    .action(ArgAction::Set)
                    .help("Store the header separately from the file"),
            )
            .arg(
                Arg::new("recursive")
                    .short('r')
                    .long("recursive")
                    .action(ArgAction::SetTrue)
                    .help("Pack directories recursively (default behavior; retained for compatibility)"),
            )
            .arg(
                Arg::new("keyfile")
                    .short('k')
                    .long("keyfile")
                    .value_name("file")
                    .action(ArgAction::Set)
                    .help("Use a keyfile instead of a password"),
            )
            .arg(
                Arg::new("hash")
                    .short('H')
                    .long("hash")
                    .action(ArgAction::SetTrue)
                    .help("Return a BLAKE3 hash of the encrypted file"),
            )
            .arg(
                Arg::new("force")
                    .short('f')
                    .long("force")
                    .action(ArgAction::SetTrue)
                    .help("Force all actions"),
            )
        )
        .subcommand(
            Command::new("unpack")
                .short_flag('u')
                .about("Unpack a previously-packed file")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The file to decrypt"),
                )
                .arg(
                    Arg::new("output")
                        .value_name("output")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The output file"),
                )
                .arg(
                    Arg::new("keyfile")
                        .short('k')
                        .long("keyfile")
                        .value_name("file")
                        .action(ArgAction::Set)
                        .help("Use a keyfile instead of a password"),
                )
                .arg(
                    Arg::new("header")
                        .long("header")
                        .value_name("file")
                        .action(ArgAction::Set)
                        .help("Use a header file that was dumped"),
                )
                .arg(
                    Arg::new("delete-input")
                        .long("delete-input")
                        .action(ArgAction::SetTrue)
                        .help("Delete the encrypted input after a successful unpack"),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .action(ArgAction::SetTrue)
                        .help("Show a detailed output"),
                )
                .arg(
                    Arg::new("hash")
                        .short('H')
                        .long("hash")
                        .action(ArgAction::SetTrue)
                        .help("Return a BLAKE3 hash of the encrypted file"),
                )
                .arg(
                    Arg::new("force")
                        .short('f')
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Force all actions"),
                )
        )
        .subcommand(Command::new("key")
                .about("Manipulate keys within the header (for advanced users")
                .subcommand_required(true)
                .subcommand(
                    Command::new("change")
                        .about("Change an encrypted file's key")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file/header file"),
                        )
                        .arg(
                            Arg::new("autogenerate")
                                .long("auto")
                                .value_name("# of words")
                                .num_args(0..=1)
                                .default_missing_value("7")
                                .value_parser(validate_autogenerate_words)
                                .action(ArgAction::Set)
                                .require_equals(true)
                                .help("Autogenerate a passphrase (default is 7 words)")
                                .conflicts_with("keyfile-new"),
                        )
                        .arg(
                            Arg::new("keyfile-old")
                                .short('k')
                                .long("keyfile-old")
                                .value_name("file")
                                .action(ArgAction::Set)
                                .help("Use an old keyfile to decrypt the master key"),
                        )
                        .arg(
                            Arg::new("keyfile-new")
                                .short('n')
                                .long("keyfile-new")
                                .value_name("file")
                                .action(ArgAction::Set)
                                .help("Use a keyfile as the new key"),
                        ),
                )
                .subcommand(
                    Command::new("add")
                        .about("Check whether a key can be added to an encrypted file")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file/header file"),
                        )
                        .arg(
                            Arg::new("keyfile-old")
                                .short('k')
                                .long("keyfile-old")
                                .value_name("file")
                                .action(ArgAction::Set)
                                .help("Use an old keyfile to decrypt the master key"),
                        ),
                )
                .subcommand(
                    Command::new("del")
                        .about("Delete a key from an encrypted file (for advanced users)")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file/header file"),
                        )
                        .arg(
                            Arg::new("keyfile")
                                .short('k')
                                .long("keyfile")
                                .value_name("file")
                                .action(ArgAction::Set)
                                .help("Use a keyfile to identify the key you want to delete"),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify that a key is correct")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file/header file"),
                        )
                        .arg(
                            Arg::new("keyfile")
                                .short('k')
                                .long("keyfile")
                                .value_name("file")
                                .action(ArgAction::Set)
                                .help("Verify a keyfile"),
                        ),
                )
         )
        .subcommand(
            Command::new("header")
                .about("Manipulate encrypted headers (for advanced users)")
                .subcommand_required(true)
                .subcommand(
                    Command::new("dump")
                        .about("Dump a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file"),
                        )
                        .arg(
                            Arg::new("output")
                                .value_name("output")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The output file"),
                        )
                        .arg(
                            Arg::new("force")
                                .short('f')
                                .long("force")
                                .action(ArgAction::SetTrue)
                                .help("Force all actions"),
                        ),
                )
                .subcommand(
                    Command::new("restore")
                        .about("Restore a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The dumped header file"),
                        )
                        .arg(
                            Arg::new("output")
                                .value_name("output")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file"),
                        ),
                )
                .subcommand(
                    Command::new("strip")
                        .about("Strip a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file"),
                        ),
                )
                .subcommand(
                    Command::new("details")
                        .about("Show details of a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted/header file"),
                        ),
                ),
        )
}

pub fn get_matches() -> clap::ArgMatches {
    build_cli().get_matches()
}

#[cfg(test)]
mod tests {
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
    fn encrypt_help_does_not_panic_from_duplicate_args() {
        let result = std::panic::catch_unwind(|| {
            let _ = super::build_cli().try_get_matches_from(["dexios", "encrypt", "--help"]);
        });

        assert!(result.is_ok(), "encrypt --help should not panic");
    }

    #[test]
    fn encrypt_command_accepts_header_and_auto() {
        let matches = super::build_cli()
            .try_get_matches_from([
                "dexios", "encrypt", "--header", "file.hdr", "--auto=7", "in.bin", "out.enc",
            ])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "encrypt", "--auto", "in.bin", "out.enc"])
            .expect("CLI should parse");
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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "hash", "one.bin", "two.bin"])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "pack", "dir-a", "dir-b", "archive.dex"])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "pack", "--auto", "dir-a", "archive.dex"])
            .expect("CLI should parse");
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
        let encrypt = super::build_cli()
            .try_get_matches_from(["dexios", "encrypt", "--delete-input", "in.bin", "out.enc"])
            .expect("encrypt --delete-input should parse");
        let (_, encrypt) = encrypt.subcommand().expect("encrypt subcommand");
        assert!(encrypt.get_flag("delete-input"));

        let decrypt = super::build_cli()
            .try_get_matches_from(["dexios", "decrypt", "--delete-input", "in.enc", "out.bin"])
            .expect("decrypt --delete-input should parse");
        let (_, decrypt) = decrypt.subcommand().expect("decrypt subcommand");
        assert!(decrypt.get_flag("delete-input"));

        let pack = super::build_cli()
            .try_get_matches_from(["dexios", "pack", "--delete-source", "dir-a", "archive.dex"])
            .expect("pack --delete-source should parse");
        let (_, pack) = pack.subcommand().expect("pack subcommand");
        assert!(pack.get_flag("delete-source"));

        let unpack = super::build_cli()
            .try_get_matches_from(["dexios", "unpack", "--delete-input", "archive.dex", "out"])
            .expect("unpack --delete-input should parse");
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
    fn key_add_command_accepts_old_keyfile_only() {
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "key", "add", "-k", "old.key", "cipher.enc"])
            .expect("CLI should parse");

        let (name, sub) = matches.subcommand().expect("subcommand");
        assert_eq!(name, "key");
        let add = sub.subcommand_matches("add").expect("key add");
        assert_eq!(
            add.get_one::<String>("keyfile-old").map(String::as_str),
            Some("old.key")
        );
        assert_eq!(
            add.get_one::<String>("input").map(String::as_str),
            Some("cipher.enc")
        );
    }

    #[test]
    fn key_add_command_rejects_new_key_sources_while_unsupported() {
        assert_unknown_argument_is_rejected(
            [
                "dexios",
                "key",
                "add",
                "-k",
                "old.key",
                "-n",
                "new.key",
                "cipher.enc",
            ],
            "-n",
        );

        assert_unknown_argument_is_rejected(
            ["dexios", "key", "add", "--auto=7", "cipher.enc"],
            "--auto",
        );
    }

    #[test]
    fn key_change_command_accepts_old_and_new_keyfiles() {
        let matches = super::build_cli()
            .try_get_matches_from([
                "dexios",
                "key",
                "change",
                "-k",
                "old.key",
                "-n",
                "new.key",
                "cipher.enc",
            ])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "key", "change", "--auto", "cipher.enc"])
            .expect("CLI should parse");
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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "key", "del", "-k", "keyfile.bin", "cipher.enc"])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "key", "verify", "-k", "keyfile.bin", "cipher.enc"])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "header", "dump", "-f", "cipher.enc", "dump.hdr"])
            .expect("CLI should parse");

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
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "header", "restore", "dump.hdr", "cipher.enc"])
            .expect("CLI should parse");

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
    }

    #[test]
    fn header_strip_command_accepts_input() {
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "header", "strip", "cipher.enc"])
            .expect("CLI should parse");

        let (name, sub) = matches.subcommand().expect("subcommand");
        assert_eq!(name, "header");
        let strip = sub.subcommand_matches("strip").expect("header strip");
        assert_eq!(
            strip.get_one::<String>("input").map(String::as_str),
            Some("cipher.enc")
        );
    }

    #[test]
    fn header_details_command_accepts_input() {
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "header", "details", "cipher.enc"])
            .expect("CLI should parse");

        let (name, sub) = matches.subcommand().expect("subcommand");
        assert_eq!(name, "header");
        let details = sub.subcommand_matches("details").expect("header details");
        assert_eq!(
            details.get_one::<String>("input").map(String::as_str),
            Some("cipher.enc")
        );
    }
}
