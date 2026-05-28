use clap::Command;

use crate::cli::args;

pub(in crate::cli) fn header_command() -> Command {
    Command::new("header")
        .about("Manipulate encrypted headers (for advanced users)")
        .subcommand_required(true)
        .subcommand(dump_command())
        .subcommand(restore_command())
        .subcommand(strip_command())
        .subcommand(details_command())
}

fn dump_command() -> Command {
    Command::new("dump")
        .about("Dump a header")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted file"))
        .arg(args::output_arg("The output file"))
        .arg(args::force_arg())
}

fn restore_command() -> Command {
    Command::new("restore")
        .about("Restore a header")
        .arg_required_else_help(true)
        .arg(args::input_arg("The dumped header file"))
        .arg(args::output_arg("The encrypted file"))
        .arg(args::force_arg())
}

fn strip_command() -> Command {
    Command::new("strip")
        .about("Strip a header")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted file"))
        .arg(args::force_arg())
}

fn details_command() -> Command {
    Command::new("details")
        .about("Show details of a header")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted/header file"))
}
