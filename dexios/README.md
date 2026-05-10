<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## Dexios CLI

`dexios` is the command-line frontend for the Dexios format.

Current defaults for new encrypted files:

- `XChaCha20-Poly1305`
- `BLAKE3-Balloon` as the only normal KDF for new V1 writes
- V1 headers
- LE31 stream encryption

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

- The supported file format is V1-only.
- Legacy Dexios formats are intentionally unsupported after the Phase 2 refactor.
- New V1 writes do not expose alternate KDF selection; historical Argon2id
  keyslot tags are reported as unsupported historical metadata.
- The CLI no longer exposes alternate cipher selection or secure-erase flags.

## More Information

For the full documentation set, see the project book and the crate-level docs linked from the repository root README.
