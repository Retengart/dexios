use clap::{Arg, ArgAction, Command};

use crate::cli::args;

pub(in crate::cli) fn pack_command() -> Command {
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
        .arg(args::force_arg())
}

pub(in crate::cli) fn unpack_command() -> Command {
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
        .arg(args::force_arg())
}
