## Directory Packing

`pack` creates a temporary zip archive and then encrypts that archive with the normal Dexios file-encryption flow. `unpack` performs the reverse operation.

The resulting encrypted file is still just a Dexios-encrypted blob. After decryption, the packed payload is an ordinary zip archive.

## Current CLI Behavior

The current CLI accepts one or more input directories:

```bash
dexios pack photos/ archive.enc
```

```bash
dexios pack photos/ videos/ archive.enc
```

`--recursive` is retained for compatibility, but recursive traversal is already the default behavior.

Compression is optional:

```bash
dexios pack --zstd photos/ archive.enc
```

## Archive Creation

The current implementation:

1. validates the input directories
2. derives unique archive root names for the provided inputs
3. excludes the output file and detached header path from being re-packed
4. creates a temporary zip artifact
5. writes directory and file entries into the archive
6. encrypts the temporary archive using the same V5 stream-mode encryption path used for normal files
7. cleans up the temporary archive

Files are currently copied into the zip archive in streaming chunks. The code does not attempt to preserve full original filesystem metadata as a stable compatibility guarantee.

## Unpacking

The current unpack flow is stricter than the historical docs:

1. decrypt the packed file into a temporary zip artifact
2. normalize every archive path before writing anything to disk
3. reject traversal attempts and duplicate output paths after normalization
4. reject unsafe symlink-based output escapes through the storage layer
5. create directories and files under the requested output root
6. clean up the temporary archive

If the CLI is not run with `--force`, unpack may prompt before overwriting existing files.

## Security Notes

- Packing hides original directory layout inside the encrypted payload, but the outer ciphertext still leaks overall file size.
- Unpack should still be treated as a risky operation on untrusted input, even though the current implementation has explicit path-safety checks.
- The temporary decrypted archive is plaintext while it exists, even though Dexios attempts to clean it up afterwards.
