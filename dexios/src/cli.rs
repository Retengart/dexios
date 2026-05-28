use clap::{Arg, ArgAction, Command};
use core::key::PassphraseWordCount;

mod args;
mod commands;
pub mod prompt;

fn validate_autogenerate_words(words: &str) -> Result<String, String> {
    let parsed = words
        .parse::<u16>()
        .map_err(|_| "generated passphrase word count must be a positive integer".to_owned())?;
    PassphraseWordCount::try_new(parsed)
        .map_err(|_| "generated passphrase word count must be a positive integer".to_owned())?;
    Ok(words.to_owned())
}

// this assembles the clap subcommands and arguments
// it returns the ArgMatches so that a match statement can send everything to the correct place
#[allow(clippy::too_many_lines)]
pub fn build_cli() -> Command {
    Command::new("dexios")
        .version(clap::crate_version!())
        .author(clap::crate_authors!("\n"))
        .about("Secure, fast and modern command-line encryption of files.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(commands::stream::encrypt_command())
        .subcommand(commands::stream::decrypt_command())
        .subcommand(commands::hash::hash_command())
        .subcommand(commands::archive::pack_command())
        .subcommand(commands::archive::unpack_command())
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
