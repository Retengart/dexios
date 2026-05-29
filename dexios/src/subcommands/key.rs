use crate::cli::prompt::get_answer;
use crate::global::states::ForceMode;
use crate::global::states::Key;
use crate::global::states::PasswordState;
use crate::global::structs::KeyManipulationParams;
use anyhow::Result;
use std::path::Path;

use super::errors::map_key_error;
use crate::info;

// Confirms a destructive keyslot mutation before it happens. The default answer
// is No, so an empty line aborts; `--force`/`-f` short-circuits to Yes via
// `get_answer`. Returns whether the caller may proceed with the mutation.
fn confirm_destructive_keyslot_change(input: &str, force: ForceMode) -> Result<bool> {
    let prompt = format!("This will permanently rewrite the keyslots of {input} - are you sure?");
    get_answer(&prompt, false, force)
}

fn reject_dual_stdin_keyfiles(params: &KeyManipulationParams) -> Result<()> {
    if params.key_old.reads_stdin() && params.key_new.reads_stdin() {
        anyhow::bail!(
            "--keyfile-old - and --keyfile-new - cannot both read from stdin; pass one key through a file, prompt, or environment variable"
        );
    }
    Ok(())
}

pub fn add(input: &str, params: &KeyManipulationParams) -> Result<()> {
    reject_dual_stdin_keyfiles(params)?;
    let intent = domain::key::add::AddIntent::new(Path::new(input)).map_err(map_key_error)?;

    if params.key_old == Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = params.key_old.get_secret(&PasswordState::Direct)?;
    let proven = intent.verify_old_key(raw_key_old).map_err(map_key_error)?;

    if params.key_new == Key::User {
        info!("Please enter your new key below");
    }

    let raw_key_new = params.key_new.get_secret(&PasswordState::Validate)?;

    domain::key::add::execute(proven, raw_key_new, params.kdf).map_err(map_key_error)?;

    Ok(())
}

pub fn change(input: &str, params: &KeyManipulationParams) -> Result<()> {
    reject_dual_stdin_keyfiles(params)?;
    let intent = domain::key::change::ChangeIntent::new(Path::new(input)).map_err(map_key_error)?;

    if params.key_old == Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = params.key_old.get_secret(&PasswordState::Direct)?;
    let proven = intent.verify_old_key(raw_key_old).map_err(map_key_error)?;

    if params.key_new == Key::User {
        info!("Please enter your new key below");
    }

    let raw_key_new = params.key_new.get_secret(&PasswordState::Validate)?;

    if !confirm_destructive_keyslot_change(input, params.force)? {
        return Ok(());
    }

    domain::key::change::execute(proven, raw_key_new, params.kdf).map_err(map_key_error)?;

    Ok(())
}

pub fn delete(input: &str, key_old: &Key, force: ForceMode) -> Result<()> {
    let intent = domain::key::delete::DeleteIntent::new(Path::new(input)).map_err(map_key_error)?;

    if key_old == &Key::User {
        info!("Please enter your key below");
    }

    let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

    if !confirm_destructive_keyslot_change(input, force)? {
        return Ok(());
    }

    domain::key::delete::execute(intent, raw_key_old).map_err(map_key_error)?;

    Ok(())
}

pub fn verify(input: &str, key: &Key) -> Result<()> {
    let intent = domain::key::verify::VerifyIntent::new(Path::new(input)).map_err(map_key_error)?;

    if key == &Key::User {
        info!("Please enter your key below");
    }

    let raw_key = key.get_secret(&PasswordState::Direct)?;

    domain::key::verify::execute(intent, raw_key).map_err(map_key_error)?;

    Ok(())
}
