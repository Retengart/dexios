<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## Dexios CLI

`dexios` is the command-line frontend for the Dexios format.

Current defaults for new encrypted files:

- `XChaCha20-Poly1305`
- `BLAKE3-Balloon`
- V5 headers
- stream-mode encryption

## Install

```bash
cargo install dexios --locked
```

Dexios currently requires Rust `1.88` or newer when built from source.

## Basic Usage

Encrypt a file:

```bash
dexios encrypt secret.txt secret.enc
```

Decrypt it again:

```bash
dexios decrypt secret.enc secret.txt
```

Pack and encrypt directories:

```bash
dexios pack photos/ archive.enc
```

Unpack a previously packed archive:

```bash
dexios unpack archive.enc output-dir
```

## Key Input

The CLI can obtain key material from:

- interactive password entry
- `--keyfile`
- `--auto`
- `DEXIOS_KEY`

Current precedence is:

1. explicit keyfile
2. explicit `--auto`
3. `DEXIOS_KEY`
4. interactive prompt

## Compatibility Notes

- New encryption uses stream mode only.
- Older memory-mode files are still supported for decryption.
- `Deoxys-II-256` is recognized for backward compatibility, but the CLI does not expose it as a new-encryption option.

## More Information

For the full documentation set, see the project book and the crate-level docs linked from the repository root README.
