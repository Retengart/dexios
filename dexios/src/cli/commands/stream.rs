use clap::Command;

use crate::cli::args;

pub(in crate::cli) fn encrypt_command() -> Command {
    Command::new("encrypt")
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
        .arg(args::force_arg())
}

pub(in crate::cli) fn decrypt_command() -> Command {
    Command::new("decrypt")
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
        .arg(args::force_arg())
}
