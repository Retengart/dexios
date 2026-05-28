use clap::{Arg, ArgAction, Command};
use core::key::PassphraseWordCount;

mod args;
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
        .arg(args::input_arg("The file to encrypt"))
        .arg(args::output_arg("The output file"))
        .arg(args::keyfile_arg())
        .arg(args::delete_input_arg(
            "Delete the input file after a successful encrypt",
        ))
        .arg(args::hash_arg())
        .arg(args::autogenerate_arg(
            "Autogenerate a passphrase (default is 7 words)",
            "keyfile",
        ))
        .arg(args::detached_header_output_arg())
        .arg(args::force_arg());

    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt a file")
        .arg(args::input_arg("The file to decrypt"))
        .arg(args::output_arg("The output file"))
        .arg(args::keyfile_arg())
        .arg(args::detached_header_input_arg())
        .arg(args::delete_input_arg(
            "Delete the input file after a successful decrypt",
        ))
        .arg(args::hash_arg())
        .arg(args::force_arg());

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
                .arg(args::output_arg("The output file"))
                .arg(args::delete_source_arg())
                .arg(args::verbose_arg())
                .arg(args::autogenerate_arg(
                    "Autogenerate a passphrase (default is 7 words)",
                    "keyfile",
                ))
                .arg(args::detached_header_output_arg())
                .arg(args::recursive_arg())
                .arg(args::keyfile_arg())
                .arg(args::hash_arg())
                .arg(args::force_arg()),
        )
        .subcommand(
            Command::new("unpack")
                .short_flag('u')
                .about("Unpack a previously-packed file")
                .arg(args::input_arg("The file to decrypt"))
                .arg(args::output_arg("The output file"))
                .arg(args::keyfile_arg())
                .arg(args::detached_header_input_arg())
                .arg(args::delete_input_arg(
                    "Delete the encrypted input after a successful unpack",
                ))
                .arg(args::verbose_arg())
                .arg(args::hash_arg())
                .arg(args::force_arg()),
        )
        .subcommand(
            Command::new("key")
                .about("Manipulate keys within the header (for advanced users")
                .subcommand_required(true)
                .subcommand(
                    Command::new("change")
                        .about("Change an encrypted file's key")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The encrypted file/header file"))
                        .arg(args::autogenerate_arg(
                            "Autogenerate a passphrase (default is 7 words)",
                            "keyfile-new",
                        ))
                        .arg(args::keyfile_old_arg())
                        .arg(args::keyfile_new_arg()),
                )
                .subcommand(
                    Command::new("add")
                        .about("Add a key to an encrypted file")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The encrypted file/header file"))
                        .arg(args::autogenerate_arg(
                            "Autogenerate a passphrase for the new key",
                            "keyfile-new",
                        ))
                        .arg(args::keyfile_old_arg())
                        .arg(args::keyfile_new_arg()),
                )
                .subcommand(
                    Command::new("del")
                        .about("Delete a key from an encrypted file (for advanced users)")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The encrypted file/header file"))
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
                        .arg(args::input_arg("The encrypted file/header file"))
                        .arg(
                            Arg::new("keyfile")
                                .short('k')
                                .long("keyfile")
                                .value_name("file")
                                .action(ArgAction::Set)
                                .help("Verify a keyfile"),
                        ),
                ),
        )
        .subcommand(
            Command::new("header")
                .about("Manipulate encrypted headers (for advanced users)")
                .subcommand_required(true)
                .subcommand(
                    Command::new("dump")
                        .about("Dump a header")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The encrypted file"))
                        .arg(args::output_arg("The output file"))
                        .arg(args::force_arg()),
                )
                .subcommand(
                    Command::new("restore")
                        .about("Restore a header")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The dumped header file"))
                        .arg(args::output_arg("The encrypted file"))
                        .arg(args::force_arg()),
                )
                .subcommand(
                    Command::new("strip")
                        .about("Strip a header")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The encrypted file"))
                        .arg(args::force_arg()),
                )
                .subcommand(
                    Command::new("details")
                        .about("Show details of a header")
                        .arg_required_else_help(true)
                        .arg(args::input_arg("The encrypted/header file")),
                ),
        )
}

pub fn get_matches() -> clap::ArgMatches {
    build_cli().get_matches()
}

#[cfg(test)]
mod tests;
