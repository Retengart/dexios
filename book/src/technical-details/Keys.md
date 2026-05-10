## Obtaining the Key

Dexios represents secrets with `Protected<>` values where possible. In practice, key material is read, normalized into bytes, wrapped, and then passed to the selected hashing flow.

The CLI rejects empty key material.

## Autogenerating a Key

`--auto` uses Dexios' bundled wordlist to generate a passphrase. The current implementation generates `n` random words joined with `-`, with `7` words used by default.

The generated passphrase is intentionally shown to the user because it is the only copy the user receives. This disclosure can be captured by terminal scrollback or logs. Dexios treats this output as deliberate disclosure, not as an accidental leak, and still keeps the returned key bytes inside `Protected<Vec<u8>>`.

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

Prompt strings are wrapped in `zeroize::Zeroizing<String>` as soon as they are read. This applies to direct prompts, confirmation prompts, mismatch retries, empty-input retries, and prompt-error paths.

On success, the accepted prompt string is copied into `Protected<Vec<u8>>`. The prompt temporaries remain `Zeroizing<String>` values and are cleared when dropped.

## Reading from a Keyfile

Dexios reads the keyfile bytes as-is and wraps them in `Protected<Vec<u8>>`.

If the keyfile path is `-`, Dexios reads the key material from standard input instead of a filesystem path.

## Reading from Environment Variables

If `DEXIOS_KEY` is available and no higher-priority key source is selected, Dexios reads it, converts it to bytes, and wraps it in `Protected<Vec<u8>>`.
