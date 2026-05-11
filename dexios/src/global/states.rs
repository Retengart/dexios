// this file contains enums found all around the codebase
// they act as toggles for certain features, so they can be
// enabled if selected by the user

use anyhow::{Context, Result};
use clap::ArgMatches;
use core::protected::Protected;

use crate::cli::prompt::get_password;
use crate::warn;
use core::key::generate_passphrase;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DirectoryMode {
    Singular,
    Recursive,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DeleteSource {
    Delete,
    Retain,
}

#[derive(PartialEq, Eq)]
pub enum PrintMode {
    Verbose,
    Quiet,
}

pub enum HeaderLocation {
    Embedded,
    Detached(String),
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DeleteInput {
    Delete,
    Retain,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum ForceMode {
    Force,
    Prompt,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Key {
    Keyfile(String),
    Env,
    Generate(i32),
    User,
}

#[derive(PartialEq, Eq)]
pub enum PasswordState {
    Validate,
    Direct, // maybe not the best name
}

fn get_bytes<R: std::io::Read>(reader: &mut R) -> Result<Protected<Vec<u8>>> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .context("Unable to read data")?;
    Ok(Protected::new(data))
}

fn generated_passphrase_disclosure(passphrase: &str) -> String {
    format!(
        "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: {passphrase}"
    )
}

fn generated_passphrase_secret<F>(total_words: &i32, mut disclose: F) -> Protected<Vec<u8>>
where
    F: FnMut(&str),
{
    let passphrase = generate_passphrase(total_words);
    let key = passphrase.with_exposed(|passphrase| {
        let message = generated_passphrase_disclosure(passphrase);
        disclose(&message);
        Protected::new(passphrase.as_bytes().to_vec())
    });
    drop(passphrase);
    key
}

impl Key {
    pub(crate) fn resolve_key_source(
        keyfile: Option<&str>,
        autogenerate: Option<&str>,
        env_available: bool,
        params: &KeyParams,
    ) -> Result<Self> {
        let key = if let (Some(path), true) = (keyfile, params.keyfile) {
            Key::Keyfile(path.to_owned())
        } else if let (Some(words), true) = (autogenerate, params.autogenerate) {
            let result = words.parse::<i32>();
            if let Ok(value) = result {
                Key::Generate(value)
            } else {
                warn!("No amount of words specified - using the default.");
                Key::Generate(7)
            }
        } else if env_available && params.env {
            Key::Env
        } else if params.user {
            Key::User
        } else {
            return Err(anyhow::anyhow!(
                "No key sources found with the parameters/arguments provided"
            ));
        };

        Ok(key)
    }

    // this handles getting the secret, and returning it
    // it relies on `parameters.rs`' handling and logic to determine which route to get the key
    // it can handle keyfiles, env variables, automatically generating and letting the user enter a key
    // it has a check for if the keyfile is empty or not
    pub fn get_secret(&self, pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
        let secret = match self {
            Key::Keyfile(path) if path == "-" => {
                let mut reader = std::io::stdin();
                let secret = get_bytes(&mut reader)?;
                if secret.with_exposed(|secret| secret.is_empty()) {
                    return Err(anyhow::anyhow!("STDIN is empty"));
                }
                secret
            }
            Key::Keyfile(path) => {
                let mut reader = std::fs::File::open(path)
                    .with_context(|| format!("Unable to read file: {path}"))?;
                let secret = get_bytes(&mut reader)?;
                if secret.with_exposed(|secret| secret.is_empty()) {
                    return Err(anyhow::anyhow!(format!("Keyfile '{path}' is empty")));
                }
                secret
            }
            Key::Env => Protected::new(
                std::env::var("DEXIOS_KEY")
                    .context("Unable to read DEXIOS_KEY from environment variable")?
                    .into_bytes(),
            ),
            Key::User => get_password(pass_state)?,
            Key::Generate(i) => generated_passphrase_secret(i, |message| warn!("{message}")),
        };

        if secret.with_exposed(|secret| secret.is_empty()) {
            Err(anyhow::anyhow!("The specified key is empty!"))
        } else {
            Ok(secret)
        }
    }

    pub fn init(
        sub_matches: &ArgMatches,
        params: &KeyParams,
        keyfile_descriptor: &str,
    ) -> Result<Self> {
        let keyfile = sub_matches
            .try_get_one::<String>(keyfile_descriptor)
            .ok()
            .flatten()
            .map(String::as_str);
        let autogenerate = sub_matches
            .try_get_one::<String>("autogenerate")
            .ok()
            .flatten()
            .map(String::as_str);

        Self::resolve_key_source(
            keyfile,
            autogenerate,
            std::env::var("DEXIOS_KEY").is_ok(),
            params,
        )
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct KeyParams {
    pub user: bool,
    pub env: bool,
    pub autogenerate: bool,
    pub keyfile: bool,
}

impl KeyParams {
    pub fn default() -> Self {
        KeyParams {
            user: true,
            env: true,
            autogenerate: true,
            keyfile: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCLOSURE_PREFIX: &str = "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: ";

    #[test]
    fn generated_passphrase_disclosure_message_includes_secret() {
        let message = generated_passphrase_disclosure("alpha-beta");

        assert!(
            message.contains("intentionally shown"),
            "generated passphrase disclosure should state intentional display: {message}"
        );
        assert!(
            message.contains("terminal scrollback") || message.contains("logs"),
            "generated passphrase disclosure should warn about terminal/log capture: {message}"
        );
        assert!(
            message.contains("alpha-beta"),
            "generated passphrase disclosure should keep the secret available to the user: {message}"
        );
    }

    #[test]
    fn generated_passphrase_secret_discloses_once_and_returns_same_bytes() {
        let mut messages = Vec::new();

        let key = generated_passphrase_secret(&3, |message| messages.push(message.to_owned()));

        assert_eq!(messages.len(), 1);
        let phrase = messages[0]
            .strip_prefix(DISCLOSURE_PREFIX)
            .expect("generated passphrase message should use the CLI disclosure prefix");
        assert_eq!(phrase.split('-').count(), 3);
        assert!(key.with_exposed(|key| key == phrase.as_bytes()));
    }

    #[test]
    fn generated_passphrase_secret_uses_closure_scoped_access() {
        let source = include_str!("states.rs");
        let required = ["passphrase", "with_exposed"].join(".");
        let forbidden = ["passphrase", "expose("].join(".");

        assert!(source.contains(&required));
        assert!(!source.contains(&forbidden));
    }

    #[test]
    fn generated_passphrase_debug_does_not_disclose_secret() {
        let mut messages = Vec::new();

        let key = generated_passphrase_secret(&2, |message| messages.push(message.to_owned()));
        let phrase = messages[0]
            .strip_prefix(DISCLOSURE_PREFIX)
            .expect("generated passphrase message should use the CLI disclosure prefix");

        assert!(!format!("{key:?}").contains(phrase));
        assert!(!format!("{:?}", Key::Generate(2)).contains(phrase));
    }
}
