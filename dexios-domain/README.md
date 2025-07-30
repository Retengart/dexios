<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

# Dexios-Domain

## What is it?

Dexios-Domain is a library used within the Dexios ecosystem to facilitate modular and well-tested components.

## Security

Dexios-Domain uses modern, secure and audited AEAD for encryption and decryption.

You may find the audit for XChaCha20-Poly1305 on [the NCC Group's website](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).

## Who uses Dexios-Domain?

This library is implemented by [Dexios](https://github.com/brxken128/dexios), a secure command-line file encryption utility.

Dexios-Domain is essentially Dexios' backend. It uses [Dexios-Core](https://github.com/brxken128/dexios-core) for headers and cryptographic functions and exposes an extremely simple API for all of Dexios' functionality.

## Features

- Convenient API for encrypt/decrypt
- XChaCha20-Poly1305 AEAD
- Authentication with ease
- Easy management of encrypted headers (no more worrying about where to store a nonce!)
- Easy `balloon` hashing with secure parameters and BLAKE3
- Frequent updates and feature additions!

## Donating

If you like my work, and want to help support Dexios, Dexios-Core or Dexios-Domain, feel free to donate! This is not necessary by any means, so please don't feel obliged to do so.

```
XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
```

## Examples

```rust
let file = File::open("my-super-secret-file").unwrap();
let secret_data = "This is some test data!".as_bytes();
let secret_pw = "mysupersecretpassword";

let encrypt_request = dexios_domain::encrypt::Request::new(&secret_pw, &secret_data);

let encrypted_data = dexios_domain::encrypt::execute(encrypt_request).unwrap();

let decrypt_request = dexios_domain::decrypt::Request::new(&secret_pw, &encrypted_data);

let decrypted_data = dexios_domain::decrypt::execute(decrypt_request).unwrap();

assert_eq!(secret_data, decrypted_data);
```

You can read more about Dexios, Dexios-Core, Dexios-Domain and the technical details [in the project's main documentation](https://brxken128.github.io/dexios/)!

## Thank you!

Dexios-Domain exclusively uses AEADs provided by the [RustCrypto Team](https://github.com/RustCrypto), so I'd like to give them a huge thank you for their hard work (this wouldn't have been possible without them!)
