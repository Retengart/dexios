#![forbid(unsafe_code)]
#![warn(clippy::all)]

use anyhow::Result;
use clap::ArgMatches;

mod cli;
mod global;
mod subcommands;

// this is where subcommand function calling is handled
// it goes hand-in-hand with `subcommands.rs`
// it works so that's good enough, and any changes are rather simple to make to it
// it handles the calling of other functions, and some (minimal) argument parsing
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let matches = cli::get_matches();
    CliRoute::from_matches(&matches)?.dispatch()
}

#[derive(Debug)]
enum CliRoute<'a> {
    Encrypt(&'a ArgMatches),
    Decrypt(&'a ArgMatches),
    Pack(&'a ArgMatches),
    Unpack(&'a ArgMatches),
    Hash(&'a ArgMatches),
    Header(&'a ArgMatches),
    Key(&'a ArgMatches),
}

impl<'a> CliRoute<'a> {
    fn from_matches(matches: &'a ArgMatches) -> Result<Self> {
        match matches.subcommand() {
            Some(("encrypt", sub_matches)) => Ok(Self::Encrypt(sub_matches)),
            Some(("decrypt", sub_matches)) => Ok(Self::Decrypt(sub_matches)),
            Some(("pack", sub_matches)) => Ok(Self::Pack(sub_matches)),
            Some(("unpack", sub_matches)) => Ok(Self::Unpack(sub_matches)),
            Some(("hash", sub_matches)) => Ok(Self::Hash(sub_matches)),
            Some(("header", sub_matches)) => Ok(Self::Header(sub_matches)),
            Some(("key", sub_matches)) => Ok(Self::Key(sub_matches)),
            Some((name, _)) => anyhow::bail!(
                "internal CLI adapter error: unsupported top-level command '{name}' after clap validation"
            ),
            None => anyhow::bail!(
                "internal CLI adapter error: missing top-level command after clap validation"
            ),
        }
    }

    fn dispatch(self) -> Result<()> {
        match self {
            Self::Encrypt(sub_matches) => subcommands::encrypt(sub_matches),
            Self::Decrypt(sub_matches) => subcommands::decrypt(sub_matches),
            Self::Pack(sub_matches) => subcommands::pack(sub_matches),
            Self::Unpack(sub_matches) => subcommands::unpack(sub_matches),
            Self::Hash(sub_matches) => subcommands::hash_stream(sub_matches),
            Self::Header(sub_matches) => dispatch_header(sub_matches),
            Self::Key(sub_matches) => dispatch_key(sub_matches),
        }
    }
}

fn dispatch_header(sub_matches: &ArgMatches) -> Result<()> {
    match sub_matches.subcommand() {
        Some(("dump", _)) => subcommands::header_dump(sub_matches),
        Some(("restore", _)) => subcommands::header_restore(sub_matches),
        Some(("strip", _)) => subcommands::header_strip(sub_matches),
        Some(("details", _)) => subcommands::header_details(sub_matches),
        _ => Ok(()),
    }
}

fn dispatch_key(sub_matches: &ArgMatches) -> Result<()> {
    match sub_matches.subcommand() {
        Some(("change", _)) => subcommands::key_change(sub_matches),
        Some(("add", _)) => subcommands::key_add(sub_matches),
        Some(("del", _)) => subcommands::key_del(sub_matches),
        Some(("verify", _)) => subcommands::key_verify(sub_matches),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod route_tests {
    use clap::Command;

    use super::CliRoute;

    #[test]
    fn cli_route_missing_top_level_command_is_adapter_error() {
        let matches = Command::new("dexios")
            .try_get_matches_from(["dexios"])
            .expect("permissive synthetic command should parse without a subcommand");

        let error = CliRoute::from_matches(&matches)
            .expect_err("missing top-level route should be rejected by the adapter");
        let message = error.to_string();

        assert!(message.contains("internal CLI adapter error"));
        assert!(message.contains("missing top-level command"));
    }

    #[test]
    fn cli_route_unsupported_top_level_command_names_command() {
        let matches = Command::new("dexios")
            .subcommand(Command::new("unknown"))
            .try_get_matches_from(["dexios", "unknown"])
            .expect("synthetic command should parse unsupported adapter route");

        let error = CliRoute::from_matches(&matches)
            .expect_err("unsupported top-level route should be rejected by the adapter");
        let message = error.to_string();

        assert!(message.contains("internal CLI adapter error"));
        assert!(message.contains("unknown"));
    }

    fn synthetic_nested_cli(parent: &'static str, leaf: Option<&'static str>) -> Command {
        let parent_command = match leaf {
            Some(leaf) => Command::new(parent).subcommand(Command::new(leaf)),
            None => Command::new(parent),
        };

        Command::new("dexios").subcommand(parent_command)
    }

    fn dispatch_error<const N: usize>(command: Command, args: [&str; N]) -> String {
        let matches = command
            .try_get_matches_from(args)
            .expect("synthetic command should parse adapter route state");

        let error = CliRoute::from_matches(&matches)
            .and_then(|route| route.dispatch())
            .expect_err("adapter route state should be rejected");

        error.to_string()
    }

    #[test]
    fn nested_route_missing_header_leaf_is_adapter_error() {
        let message = dispatch_error(synthetic_nested_cli("header", None), ["dexios", "header"]);

        assert!(message.contains("internal CLI adapter error"));
        assert!(message.contains("missing header command"));
    }

    #[test]
    fn nested_route_unsupported_header_leaf_names_command() {
        let message = dispatch_error(
            synthetic_nested_cli("header", Some("unknown-header")),
            ["dexios", "header", "unknown-header"],
        );

        assert!(message.contains("internal CLI adapter error"));
        assert!(message.contains("unsupported header command"));
        assert!(message.contains("unknown-header"));
    }

    #[test]
    fn nested_route_missing_key_leaf_is_adapter_error() {
        let message = dispatch_error(synthetic_nested_cli("key", None), ["dexios", "key"]);

        assert!(message.contains("internal CLI adapter error"));
        assert!(message.contains("missing key command"));
    }

    #[test]
    fn nested_route_unsupported_key_leaf_names_command() {
        let message = dispatch_error(
            synthetic_nested_cli("key", Some("unknown-key")),
            ["dexios", "key", "unknown-key"],
        );

        assert!(message.contains("internal CLI adapter error"));
        assert!(message.contains("unsupported key command"));
        assert!(message.contains("unknown-key"));
    }
}
