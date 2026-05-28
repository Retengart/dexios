use clap::{Arg, ArgAction, Command};

pub(in crate::cli) fn hash_command() -> Command {
    Command::new("hash").about("Hash files with BLAKE3").arg(
        Arg::new("input")
            .value_name("input")
            .action(ArgAction::Set)
            .required(true)
            .help("The file(s) to hash")
            .num_args(1..),
    )
}
