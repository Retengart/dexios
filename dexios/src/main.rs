#![deny(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "tests assert exact behavior and may panic on failure"
    )
)]

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
    Header(HeaderRoute<'a>),
    Key(KeyRoute<'a>),
}

impl<'a> CliRoute<'a> {
    fn from_matches(matches: &'a ArgMatches) -> Result<Self> {
        match matches.subcommand() {
            Some(("encrypt", sub_matches)) => Ok(Self::Encrypt(sub_matches)),
            Some(("decrypt", sub_matches)) => Ok(Self::Decrypt(sub_matches)),
            Some(("pack", sub_matches)) => Ok(Self::Pack(sub_matches)),
            Some(("unpack", sub_matches)) => Ok(Self::Unpack(sub_matches)),
            Some(("hash", sub_matches)) => Ok(Self::Hash(sub_matches)),
            Some(("header", sub_matches)) => {
                Ok(Self::Header(HeaderRoute::from_matches(sub_matches)?))
            }
            Some(("key", sub_matches)) => Ok(Self::Key(KeyRoute::from_matches(sub_matches)?)),
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
            Self::Header(route) => route.dispatch(),
            Self::Key(route) => route.dispatch(),
        }
    }
}

#[derive(Debug)]
enum HeaderRoute<'a> {
    Dump(&'a ArgMatches),
    Restore(&'a ArgMatches),
    Strip(&'a ArgMatches),
    Details(&'a ArgMatches),
}

impl<'a> HeaderRoute<'a> {
    fn from_matches(matches: &'a ArgMatches) -> Result<Self> {
        match matches.subcommand() {
            Some(("dump", sub_matches)) => Ok(Self::Dump(sub_matches)),
            Some(("restore", sub_matches)) => Ok(Self::Restore(sub_matches)),
            Some(("strip", sub_matches)) => Ok(Self::Strip(sub_matches)),
            Some(("details", sub_matches)) => Ok(Self::Details(sub_matches)),
            Some((name, _)) => anyhow::bail!(
                "internal CLI adapter error: unsupported header command '{name}' after clap validation"
            ),
            None => anyhow::bail!(
                "internal CLI adapter error: missing header command after clap validation"
            ),
        }
    }

    fn dispatch(self) -> Result<()> {
        match self {
            Self::Dump(sub_matches) => subcommands::header_dump(sub_matches),
            Self::Restore(sub_matches) => subcommands::header_restore(sub_matches),
            Self::Strip(sub_matches) => subcommands::header_strip(sub_matches),
            Self::Details(sub_matches) => subcommands::header_details(sub_matches),
        }
    }
}

#[derive(Debug)]
enum KeyRoute<'a> {
    Change(&'a ArgMatches),
    Add(&'a ArgMatches),
    Del(&'a ArgMatches),
    Verify(&'a ArgMatches),
}

impl<'a> KeyRoute<'a> {
    fn from_matches(matches: &'a ArgMatches) -> Result<Self> {
        match matches.subcommand() {
            Some(("change", sub_matches)) => Ok(Self::Change(sub_matches)),
            Some(("add", sub_matches)) => Ok(Self::Add(sub_matches)),
            Some(("del", sub_matches)) => Ok(Self::Del(sub_matches)),
            Some(("verify", sub_matches)) => Ok(Self::Verify(sub_matches)),
            Some((name, _)) => anyhow::bail!(
                "internal CLI adapter error: unsupported key command '{name}' after clap validation"
            ),
            None => anyhow::bail!(
                "internal CLI adapter error: missing key command after clap validation"
            ),
        }
    }

    fn dispatch(self) -> Result<()> {
        match self {
            Self::Change(sub_matches) => subcommands::key_change(sub_matches),
            Self::Add(sub_matches) => subcommands::key_add(sub_matches),
            Self::Del(sub_matches) => subcommands::key_del(sub_matches),
            Self::Verify(sub_matches) => subcommands::key_verify(sub_matches),
        }
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
            .and_then(CliRoute::dispatch)
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
