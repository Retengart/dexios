## Obtaining the Key

Dexios represents secrets with `Protected<>` values where possible. In practice, key material is read, normalized into bytes, wrapped, and then passed to the selected hashing flow.

The CLI rejects empty key material.

## Autogenerating a Key

`--auto` uses Dexios' bundled wordlist to generate a passphrase. The current
implementation generates `n` random words joined with `-`. `--auto` without a
value defaults to `7` words.

Explicit word counts must be positive integers. `--auto=0`, `--auto=-1`, and
non-numeric values are rejected before passphrase generation and before the
generated-passphrase disclosure message is printed.

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

## V1 Key Workflows

Key workflows operate on V1 headers and keyslots only.

- `key add` remains unsupported for V1 encrypted artifacts in this refactor
  line. It fails with a typed unsupported-workflow result and does not request a
  new key or mutate the header.
- `key verify` is read-only. It reads the V1 header keyslots, attempts to unwrap
  the master key with the supplied key, and reports success, incorrect key,
  unsupported KDF, malformed header, unsupported format, or read I/O failure. It
  does not authenticate or decrypt the payload stream.
- `key change` first proves that the old key unwraps the current master key. It
  then builds a replacement header and proves that the new key unwraps the same
  master key before committing the staged header update.
- `key del` deletes only the keyslot proven by the supplied old key. It rejects
  deletion of the final usable V1 keyslot and does not collect a separate
  remaining-key verification key.

Historical V1 keyslots tagged `[0xDF, 0x02]` are recognized as unsupported
Argon2id metadata. Key mutation refuses files containing that unsupported tag
instead of skipping, normalizing, or rewriting the slot. `key verify` reports a
typed unsupported-KDF result when the unsupported tag prevents verification.

CLI key workflows perform cheap target, format, and KDF validation before
prompting for secrets where the operation permits it. `key change` asks for the
new key only after the old key has been verified against the current header.
