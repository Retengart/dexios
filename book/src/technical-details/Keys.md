## Obtaining the Key

Dexios represents secrets with `Protected<>` values where possible. In practice, key material is read, normalized into bytes, wrapped, and then passed to the selected hashing flow.

The CLI rejects empty key material.

## Autogenerating a Key

`--auto` uses Dexios' bundled wordlist to generate a passphrase. The current implementation generates `n` random words joined with `-`, with `7` words used by default.

Examples:

```text
orchard-linen-buckle-river-amber-signal-willow
```

```text
delta-frost-harbor-meadow-slate
```

## Reading from the Terminal

Interactive passwords are read with `rpassword`.

- encryption asks twice and compares the entries
- decryption asks once

The resulting string is consumed into bytes and wrapped in `Protected<Vec<u8>>`.

## Reading from a Keyfile

Dexios reads the keyfile bytes as-is and wraps them in `Protected<Vec<u8>>`.

If the keyfile path is `-`, Dexios reads the key material from standard input instead of a filesystem path.

## Reading from Environment Variables

If `DEXIOS_KEY` is available and no higher-priority key source is selected, Dexios reads it, converts it to bytes, and wraps it in `Protected<Vec<u8>>`.
