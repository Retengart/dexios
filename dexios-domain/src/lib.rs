//! ## What is it?
//!
//! Dexios-Domain is a library used as an addon to `dexios-core` that provides file-based encryption/decryption.
//!
//! ## Security
//!
//! Dexios-Domain uses modern, secure and audited AEADs for encryption and decryption.
//!
//! You may find the audit for XChaCha20-Poly1305 on [the NCC Group's website](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).
//!
//! ## Who uses Dexios-Domain?
//!
//! This library is implemented by [Dexios](https://github.com/brxken128/dexios), a secure command-line file
//! encryption utility.
//!
//! Dexios-Domain makes it easy to integrate the Dexios format into your own projects (and if there's a feature that you'd like to see, please don't hesitate to [open a Github issue](https://github.com/brxken128/dexios-domain/issues)).
//!
//! ## Donating
//!
//! If you like my work, and want to help support Dexios, or Dexios-Domain, feel free to donate! This is not necessary by any means, so please don't feel obliged to do so.
//!
//! ```text
//! XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
//! BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
//! ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
//! ```
//!
//! You can read more about Dexios, Dexios-Domain and the technical details [in the project's main documentation](https://brxken128.github.io/dexios/)!
//!
//! ## Thank you!
//!
//! Dexios-Domain exclusively uses AEADs provided by the [RustCrypto Team](https://github.com/RustCrypto), so I'd like to give them a huge thank you for their hard work (this wouldn't have been possible without them!)

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
