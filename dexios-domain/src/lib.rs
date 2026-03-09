//! `dexios-domain` is the workflow layer between the Dexios CLI and
//! `dexios-core`.
//!
//! It owns the higher-level operations that are awkward to model as raw
//! primitives alone, including:
//!
//! - encrypt/decrypt request execution,
//! - pack and unpack workflows,
//! - secure erase helpers,
//! - header dump/restore/strip operations,
//! - V5 key manipulation,
//! - and storage abstractions for the real filesystem and tests.
//!
//! The CLI primarily validates user intent and then dispatches work through
//! `dexios-domain`.
//!

// lints
#![forbid(unsafe_code)]
#![warn(
    rust_2018_idioms,
    non_ascii_idents,
    unstable_features,
    unused_imports,
    unused_qualifications,
    clippy::pedantic,
    clippy::all
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

pub mod decrypt;
pub mod encrypt;
pub mod erase;
pub mod erase_dir;
pub mod hash;
pub mod hasher;
pub mod header;
pub mod key;
pub mod overwrite;
pub mod pack;
pub mod storage;
pub mod unpack;

pub mod utils;
