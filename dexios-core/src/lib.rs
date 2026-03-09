//! `dexios-core` is the reusable cryptographic and format layer behind Dexios.
//!
//! It provides:
//!
//! - versioned Dexios header parsing and serialization,
//! - password hashing and wrapping-key derivation,
//! - stream and memory-mode cipher helpers,
//! - and `Protected<>` for explicit zeroize-on-drop secret handling.
//!
//! The current latest writable header version is [`header::HeaderVersion::V5`].
//!
//! For new encryption, the Dexios CLI currently uses `dexios-core` with
//! `XChaCha20-Poly1305` by default, `AES-256-GCM` optionally, and V5 headers in
//! stream mode. `Deoxys-II-256` remains part of the recognized format for
//! backward compatibility, but the current CLI does not expose it for new
//! encryption.
#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cipher;
pub mod header;
pub mod key;
pub mod primitives;
pub mod protected;
pub mod stream;
pub use aead::Payload;
pub use zeroize::Zeroize;

#[cfg(feature = "visual")]
pub mod visual;
