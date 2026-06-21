use clap::Command;
use core::key::PassphraseWordCount;

mod args;
mod commands;
pub(crate) mod overwrite;
pub(crate) mod prompt;

const MAX_AUTOGENERATE_WORDS: u16 = 64;

fn validate_autogenerate_words(words: &str) -> Result<String, String> {
    let parsed = words
        .parse::<u16>()
        .map_err(|_| "generated passphrase word count must be a positive integer".to_owned())?;
    PassphraseWordCount::try_new(parsed)
        .map_err(|_| "generated passphrase word count must be a positive integer".to_owned())?;
    if parsed > MAX_AUTOGENERATE_WORDS {
        return Err(format!(
            "generated passphrase word count must be between 1 and {MAX_AUTOGENERATE_WORDS}"
        ));
    }
    Ok(words.to_owned())
}

// this assembles the clap subcommands and arguments for get_matches()
pub(crate) fn build_cli() -> Command {
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
        .subcommand(commands::key::key_command())
        .subcommand(commands::header::header_command())
}

pub(crate) fn get_matches() -> clap::ArgMatches {
    build_cli().get_matches()
}

#[cfg(test)]
mod tests;
