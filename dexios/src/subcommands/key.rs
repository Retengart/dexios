// TODO(brxken128): give this file a better name
use crate::global::states::Key;
use crate::global::states::PasswordState;
use crate::global::structs::KeyManipulationParams;
use anyhow::{Context, Result};
use core::header::common::HeaderReadError;
use core::header::read_header;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Seek;

use crate::info;

fn ensure_v1_header<R: std::io::Read>(reader: &mut R) -> Result<()> {
    match read_header(reader) {
        Ok(_) => Ok(()),
        Err(HeaderReadError::InvalidMagic(_)) | Err(HeaderReadError::UnsupportedVersion(_)) => Err(
            anyhow::anyhow!("This function currently only supports Dexios V1 headers"),
        ),
        Err(err) => Err(anyhow::anyhow!("Malformed Dexios V1 header: {err}")),
    }
}

pub fn add(input: &str, key_old: &Key) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {input}"))?,
    );

    ensure_v1_header(&mut *input_file.borrow_mut())?;

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if key_old == &Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

    domain::key::add::execute(domain::key::add::Request {
        handle: &input_file,
        raw_key_old,
    })?;

    Ok(())
}

pub fn change(input: &str, params: &KeyManipulationParams) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {input}"))?,
    );

    ensure_v1_header(&mut *input_file.borrow_mut())?;

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if params.key_old == Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = params.key_old.get_secret(&PasswordState::Direct)?;

    if params.key_new == Key::User {
        info!("Please enter your new key below");
    }

    let raw_key_new = params.key_new.get_secret(&PasswordState::Validate)?;

    domain::key::change::execute(domain::key::change::Request {
        handle: &input_file,
        kdf: params.kdf,
        raw_key_old,
        raw_key_new,
    })?;

    Ok(())
}

pub fn delete(input: &str, key_old: &Key) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {input}"))?,
    );

    ensure_v1_header(&mut *input_file.borrow_mut())?;

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if key_old == &Key::User {
        info!("Please enter your key below");
    }

    let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

    domain::key::delete::execute(domain::key::delete::Request {
        handle: &input_file,
        raw_key_old,
    })?;

    Ok(())
}

pub fn verify(input: &str, key: &Key) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {input}"))?,
    );

    ensure_v1_header(&mut *input_file.borrow_mut())?;

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if key == &Key::User {
        info!("Please enter your key below");
    }

    let raw_key = key.get_secret(&PasswordState::Direct)?;

    domain::key::verify::execute(domain::key::verify::Request {
        handle: &input_file,
        raw_key,
    })?;

    Ok(())
}
