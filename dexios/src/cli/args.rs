use clap::{Arg, ArgAction};

pub(super) fn input_arg(help: &'static str) -> Arg {
    Arg::new("input")
        .value_name("input")
        .action(ArgAction::Set)
        .required(true)
        .help(help)
}

pub(super) fn output_arg(help: &'static str) -> Arg {
    Arg::new("output")
        .value_name("output")
        .action(ArgAction::Set)
        .required(true)
        .help(help)
}

pub(super) fn keyfile_arg_with_help(help: &'static str) -> Arg {
    Arg::new("keyfile")
        .short('k')
        .long("keyfile")
        .value_name("file")
        .action(ArgAction::Set)
        .help(help)
}

pub(super) fn keyfile_arg() -> Arg {
    keyfile_arg_with_help("Use a keyfile instead of a password")
}

pub(super) fn force_arg() -> Arg {
    Arg::new("force")
        .short('f')
        .long("force")
        .action(ArgAction::SetTrue)
        .help("Force all actions")
}

pub(super) fn hash_arg() -> Arg {
    Arg::new("hash")
        .short('H')
        .long("hash")
        .action(ArgAction::SetTrue)
        .help("Return a BLAKE3 hash of the encrypted file")
}

pub(super) fn delete_input_arg(help: &'static str) -> Arg {
    Arg::new("delete-input")
        .long("delete-input")
        .action(ArgAction::SetTrue)
        .help(help)
}

pub(super) fn delete_source_arg() -> Arg {
    Arg::new("delete-source")
        .long("delete-source")
        .action(ArgAction::SetTrue)
        .help("Delete the source directories after a successful pack")
}

pub(super) fn verbose_arg() -> Arg {
    Arg::new("verbose")
        .short('v')
        .long("verbose")
        .action(ArgAction::SetTrue)
        .help("Show a detailed output")
}

pub(super) fn recursive_arg() -> Arg {
    Arg::new("recursive")
        .short('r')
        .long("recursive")
        .action(ArgAction::SetTrue)
        .help("Pack directories recursively (default behavior; retained for compatibility)")
}

pub(super) fn detached_header_output_arg() -> Arg {
    Arg::new("header")
        .long("header")
        .value_name("file")
        .action(ArgAction::Set)
        .help("Store the header separately from the file")
}

pub(super) fn detached_header_input_arg() -> Arg {
    Arg::new("header")
        .long("header")
        .value_name("file")
        .action(ArgAction::Set)
        .help("Use a header file that was dumped")
}

pub(super) fn required_detached_header_backup_arg() -> Arg {
    Arg::new("header")
        .long("header")
        .value_name("file")
        .action(ArgAction::Set)
        .required(true)
        .help("Verified backup of the header being stripped (must byte-match the embedded header)")
}

pub(super) fn keyfile_old_arg() -> Arg {
    Arg::new("keyfile-old")
        .short('k')
        .long("keyfile-old")
        .value_name("file")
        .action(ArgAction::Set)
        .help("Use an old keyfile to decrypt the master key")
}

pub(super) fn keyfile_new_arg() -> Arg {
    Arg::new("keyfile-new")
        .short('n')
        .long("keyfile-new")
        .value_name("file")
        .action(ArgAction::Set)
        .help("Use a keyfile as the new key")
}

pub(super) fn autogenerate_arg(help: &'static str, conflict_target: &'static str) -> Arg {
    Arg::new("autogenerate")
        .long("auto")
        .value_name("# of words")
        .num_args(0..=1)
        .default_missing_value("7")
        .value_parser(super::validate_autogenerate_words)
        .action(ArgAction::Set)
        .require_equals(true)
        .help(help)
        .conflicts_with(conflict_target)
}
