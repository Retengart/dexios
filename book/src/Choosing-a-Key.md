## Choosing a Key

Dexios supports three practical key sources:

- an interactively entered passphrase
- a keyfile via `--keyfile`
- a generated passphrase via `--auto`

If you lose the key material for an encrypted file, Dexios cannot recover the plaintext.

## Recommended Options

For most users:

- use a strong passphrase if you want something memorable
- use a random keyfile if you want opaque machine-generated key material
- use `--auto` when you want Dexios to generate a passphrase for you

An example keyfile command:

```bash
dd if=/dev/urandom of=keyfile bs=1 count=4096
```

## Key Source Precedence

When multiple key sources are available, the current CLI resolves them in this order:

1. explicit keyfile
2. explicit `--auto`
3. interactive password entry

Dexios does not accept key material from environment variables. For noninteractive automation, use a keyfile or pass `--keyfile -` and supply the key bytes on standard input.

## Keyfiles

`--keyfile <path>` reads raw bytes from the given file. The keyfile must be non-empty and no larger than 1 MiB.

For advanced scripted use, passing `-` as the keyfile path reads the key bytes from standard input.

## Generated Passphrases

`--auto` generates a passphrase from Dexios' bundled wordlist. The current implementation generates `n` random words joined with `-`, with a default of `7` words:

```text
word-word-word-word-word-word-word
```

You can supply a custom count:

```bash
dexios encrypt --auto=5 input.txt output.enc
```
