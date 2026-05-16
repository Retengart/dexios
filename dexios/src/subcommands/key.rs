// TODO(brxken128): give this file a better name
use crate::global::states::Key;
use crate::global::states::PasswordState;
use crate::global::structs::KeyManipulationParams;
use anyhow::Result;
use std::path::Path;

use super::errors::map_key_error;
use crate::info;

pub fn add(input: &str, params: &KeyManipulationParams) -> Result<()> {
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

    domain::key::change::execute(proven, raw_key_new, params.kdf).map_err(map_key_error)?;

    Ok(())
}

pub fn delete(input: &str, key_old: &Key) -> Result<()> {
    let intent = domain::key::delete::DeleteIntent::new(Path::new(input)).map_err(map_key_error)?;

    if key_old == &Key::User {
        info!("Please enter your key below");
    }

    let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

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
