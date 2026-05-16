//! `dexios-core` is the reusable cryptographic and format layer behind Dexios.
//!
//! It provides:
//!
//! - Dexios header parsing and serialization,
//! - password hashing and wrapping-key derivation,
//! - single-suite XChaCha20-Poly1305 cipher and stream helpers,
//! - and `Protected<>` for explicit zeroize-on-drop secret handling.
#![forbid(unsafe_code)]
#![warn(clippy::all)]

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
