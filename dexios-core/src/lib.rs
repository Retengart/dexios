//! `dexios-core` is the reusable cryptographic and format layer behind Dexios.
//!
//! It provides:
//!
//! - Dexios header parsing and serialization,
//! - password hashing and wrapping-key derivation,
//! - single-suite XChaCha20-Poly1305 cipher and stream helpers,
//! - and `Protected<>` for explicit zeroize-on-drop secret handling.
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
        reason = "tests assert exact behavior and may panic on failure"
    )
)]

pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cipher;
#[path = "header/mod.rs"]
pub mod header;
pub mod kdf;
pub mod key;
pub mod payload;
pub mod primitives;
pub mod protected;
pub mod stream;
pub use aead::Payload;
pub use zeroize::Zeroize;

#[cfg(feature = "visual")]
pub mod visual;
