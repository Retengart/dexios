use clap::{Arg, Command};

use crate::cli::args;

pub(in crate::cli) fn key_command() -> Command {
    Command::new("key")
        .about("Manipulate keys within the header (for advanced users")
        .subcommand_required(true)
        .subcommand(change_command())
        .subcommand(add_command())
        .subcommand(del_command())
        .subcommand(verify_command())
}

fn change_command() -> Command {
    Command::new("change")
        .about("Change an encrypted file's key")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted file/header file"))
        .arg(autogenerate_new_key_arg(
            "Autogenerate a passphrase (default is 7 words)",
        ))
        .arg(args::keyfile_old_arg())
        .arg(args::keyfile_new_arg())
}

fn add_command() -> Command {
    Command::new("add")
        .about("Add a key to an encrypted file")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted file/header file"))
        .arg(autogenerate_new_key_arg(
            "Autogenerate a passphrase for the new key",
        ))
        .arg(args::keyfile_old_arg())
        .arg(args::keyfile_new_arg())
}

fn del_command() -> Command {
    Command::new("del")
        .about("Delete a key from an encrypted file (for advanced users)")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted file/header file"))
        .arg(args::keyfile_arg_with_help(
            "Use a keyfile to identify the key you want to delete",
        ))
}

fn verify_command() -> Command {
    Command::new("verify")
        .about("Verify that a key is correct")
        .arg_required_else_help(true)
        .arg(args::input_arg("The encrypted file/header file"))
        .arg(args::keyfile_arg_with_help("Verify a keyfile"))
}

fn autogenerate_new_key_arg(help: &'static str) -> Arg {
    args::autogenerate_arg(help, "keyfile-new").conflicts_with("keyfile-new")
}
