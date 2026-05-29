//! `dexios-domain` is the workflow layer between the Dexios CLI and
//! `dexios-core`.
//!
//! It owns the higher-level operations that are awkward to model as raw
//! primitives alone, including:
//!
//! - V1 encrypt/decrypt request execution,
//! - pack and unpack workflows,
//! - header dump/restore/strip operations,
//! - V1 keyslot manipulation over a shared wrapped master key,
//! - and storage abstractions for the real filesystem and tests.
//!
//! The CLI primarily validates user intent and then dispatches work through
//! `dexios-domain`.
//!

// lints
#![forbid(unsafe_code)]
// Library hygiene: keep stdout/stderr/process-exit out of the reusable crate.
// `missing_docs` is intentionally NOT enforced here: the public surface has a
// large pre-existing undocumented body, and promoting it under the workspace
// `-D warnings` gate would require ~1000 doc comments that would also breach the
// frozen maintainability line-count caps. Documenting it is tracked separately.
#![warn(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
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
        clippy::significant_drop_tightening,
        reason = "tests assert exact behavior and may panic on failure"
    )
)]

pub mod archive;
pub mod decrypt;
pub mod encrypt;
pub mod hash;
pub mod hasher;
pub mod header;
pub mod key;
pub mod pack;
pub mod storage;
pub mod unpack;
pub mod workflow_error;

pub mod utils;
