//! This is a library for encrypting/decrypting, password hashing, and for managing encrypted file headers.
//!
//! It contains the core functionality of [`Dexios`](https://github.com/brxken128/dexios)
//!
//! The documentation here at crates.io is always up-to-date with the newest release.
//! If you'd like to view the documentation for the current code in the repository,
//! please see [brxken128.github.io/dexios](https://brxken128.github.io/dexios).
//!
//! This library uses XChaCha20-Poly1305 for authenticated encryption with additional data.
//!
//! You may find the audit for XChaCha20-Poly1305 on [the NCC Group's website](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).
//!
//! # Core Modules
//!
//! * [`cipher`] for regular encryption/decryption
//! * [`header`] for Dexios header manipulation (serializing/deserializing, AAD generation)
//! * [`key`] for password hashing
//! * [`primitives`] for shared constants and types
//! * [`stream`] for encrypting/decrypting in stream mode (low memory usage)
//!
//! # General Workflow
//!
//! This is used as the backend for [`Dexios`](https://github.com/brxken128/dexios), but anyone can use the library.
//!
//! Please remember that Dexios-Core is provided as-is, and I cannot guarantee that it's bug-free.
//! It uses components that are deemed secure by many (XChaCha20-Poly1305, BLAKE3-Balloon hashing).
//!
//! # Donation
//! If you like my work, and want to help support it, please consider donating to me so I can continue working on Free and Open Source projects!
//!
//! You may donate to one of the addresses below. Thank you!
//!
//! BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
//!
//! XMR: 83szwpRt61GbGe9tLNneYk8cZCpoeBfSjFFMifKCSpHoHgNDUFEBD5SfL9NxHvKi5pUPhetRCvdptfyiYeCpRpNR2FgsKHj
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
