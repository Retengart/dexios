use clap::{Arg, ArgAction, Command};

pub mod prompt;

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
            Arg::new("erase")
                .long("erase")
                .value_name("# of passes")
                .action(ArgAction::Set)
                .require_equals(true)
                .help("Securely erase the input file once complete (default is 1 pass)")
                .num_args(0..=1)
                .default_missing_value("1"),
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .action(ArgAction::SetTrue)
                .help("Return a BLAKE3 hash of the encrypted file"),
        )
        .arg(
            Arg::new("argon")
                .long("argon")
                .action(ArgAction::SetTrue)
                .help("Use argon2id for password hashing"),
        )
        .arg(
            Arg::new("autogenerate")
                .long("auto")
                .value_name("# of words")
                .num_args(0..=1)
                .default_missing_value("7")
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
        )
        .arg(
            Arg::new("aes")
                .long("aes")
                .action(ArgAction::SetTrue)
                .help("Use AES-256-GCM for encryption"),
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
            Arg::new("erase")
                .long("erase")
                .value_name("# of passes")
                .action(ArgAction::Set)
                .require_equals(true)
                .help("Securely erase the input file once complete (default is 1 pass)")
                .num_args(0..=1)
                .default_missing_value("1"),
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
        .author("brxken128 <brxken128@tutanota.com>")
        .about("Secure, fast and modern command-line encryption of files.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(encrypt.clone())
        .subcommand(decrypt.clone())
        .subcommand(
            Command::new("erase")
                .about("Erase a file completely")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The file to erase"),
                )
                .arg(
                    Arg::new("force")
                        .short('f')
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Force all actions"),
                )
                .arg(
                    Arg::new("passes")
                        .long("passes")
                        .value_name("# of passes")
                        .action(ArgAction::Set)
                        .require_equals(true)
                        .help("Specify the number of passes (default is 1)")
                        .num_args(0..=1)
                        .default_missing_value("1"),
                ),
        )
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
                Arg::new("erase")
                    .long("erase")
                    .action(ArgAction::SetTrue)
                    .help("Securely erase every file from the source directory, before deleting the directory")
            )
            .arg(
                Arg::new("argon")
                    .long("argon")
                    .action(ArgAction::SetTrue)
                    .help("Use argon2id for password hashing"),
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
                Arg::new("zstd")
                    .short('z')
                    .long("zstd")
                    .action(ArgAction::SetTrue)
                    .help("Use ZSTD compression"),
            )
            .arg(
                Arg::new("recursive")
                    .short('r')
                    .long("recursive")
                    .action(ArgAction::SetTrue)
                    .help("Index files and folders within other folders (index recursively)"),
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
            .arg(
                Arg::new("aes")
                    .long("aes")
                    .action(ArgAction::SetTrue)
                    .help("Use AES-256-GCM for encryption"),
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
                    Arg::new("erase")
                        .long("erase")
                        .value_name("# of passes")
                        .action(ArgAction::Set)
                        .require_equals(true)
                        .help("Securely erase the input file once complete (default is 1 pass)")
                        .num_args(0..=1)
                        .default_missing_value("1"),
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
                                .action(ArgAction::Set)
                                .require_equals(true)
                                .help("Autogenerate a passphrase (default is 7 words)")
                                .conflicts_with("keyfile-new"),
                        )
                        .arg(
                            Arg::new("argon")
                                .long("argon")
                                .action(ArgAction::SetTrue)
                                .help("Use argon2id for password hashing"),
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
                        .about("Add a key to an encrypted file (for advanced users)")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .action(ArgAction::Set)
                                .required(true)
                                .help("The encrypted file/header file"),
                        )
                        .arg(
                            Arg::new("argon")
                                .long("argon")
                                .action(ArgAction::SetTrue)
                                .help("Use argon2id for password hashing"),
                        )
                        .arg(
                            Arg::new("autogenerate")
                                .long("auto")
                                .value_name("# of words")
                                .num_args(0..=1)
                                .default_missing_value("7")
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
    #[test]
    fn encrypt_command_accepts_header_and_auto() {
        let matches = super::build_cli()
            .try_get_matches_from([
                "dexios", "encrypt", "--header", "file.hdr", "--argon", "--auto=7", "in.bin",
                "out.enc",
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
        assert!(sub.get_flag("argon"));
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
    fn pack_command_accepts_multiple_paths_and_zstd() {
        let matches = super::build_cli()
            .try_get_matches_from(["dexios", "pack", "--zstd", "dir-a", "dir-b", "archive.dex"])
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
        assert!(sub.get_flag("zstd"));
    }

    #[test]
    fn key_add_command_accepts_old_and_new_keyfiles() {
        let matches = super::build_cli()
            .try_get_matches_from([
                "dexios",
                "key",
                "add",
                "-k",
                "old.key",
                "-n",
                "new.key",
                "cipher.enc",
            ])
            .expect("CLI should parse");

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
}
