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

Compression is not user-configurable. Pack uses the default Dexios archive
compression policy.

## Archive Creation

The current implementation:

1. validates the input directories
2. derives unique archive root names for the provided inputs
3. excludes the output file and detached header path from being re-packed
4. materializes the directory and file entry list in memory
5. checks the shared `ArchiveLimits` structural policy
6. creates an ordinary plaintext temporary zip artifact
7. writes directory and file entries into the archive
8. encrypts the temporary archive using the same V1 stream encryption path used for normal files
9. commits the final encrypted output and detached header through staged storage transaction semantics
10. drops the temporary archive

The temporary zip artifact contains plaintext source data while it exists. It is
an ordinary temporary file used as workflow scratch space. Dexios relies on
normal drop/delete cleanup for that artifact and does not treat it as secure
erase, sanitization, local temp-storage isolation, or forensic recovery
resistance.

The archive is always written with the Dexios-owned archive policy. Current pack
output uses Zstd compression for offline at-rest archival use. The public
archive contract intentionally stays small: archive path plus file/directory
distinction. Dexios does not currently guarantee preservation of permissions,
timestamps, ZIP extra fields, symlinks, extended attributes, or other filesystem
metadata as stable compatibility behavior.

## Structural Limits

Pack and unpack share the same `ArchiveLimits` defaults:

- maximum archive entries: `100000`
- maximum normalized archive path bytes: `4096`
- maximum normalized archive path depth: `64`

Pack checks these limits while materializing source entries and before ZIP
writing begins. Unpack checks entry count before metadata scanning, and checks
each normalized archive path before prompts, staging, or writes.

These are structural limits, not storage-capacity guarantees. Large directory
trees and archives still require enough memory, temp storage, and final output
space for the materialized entry lists, plaintext temporary ZIP, encrypted
output, and extracted files. Dexios does not perform a robust OS capacity proof
before starting the workflow.

The current model is bounded by indexing: pack materializes entries before
writing, and unpack pre-scans ZIP metadata, collision sets, and selected targets
before transaction commit. It is not a streaming archive redesign.

Files are currently copied into the zip archive in streaming chunks. The code does not attempt to preserve full original filesystem metadata as a stable compatibility guarantee.

## Unpacking

The current unpack flow is stricter than the historical docs:

1. decrypt the packed file into a temporary zip artifact
2. normalize every archive path before writing anything to disk
3. enforce the shared `ArchiveLimits` entry count, path byte, and path depth policy
4. reject traversal attempts, unsafe ZIP names, duplicate normalized paths, and prefix collisions
5. reject unsafe symlink-based output escapes through the storage layer
6. run overwrite prompts only after the structural validation pass succeeds
7. revalidate selected file targets near staging
8. stage selected extracted files under the requested output root
9. commit the extracted files through storage transaction semantics
10. clean up the temporary archive

If the CLI is not run with `--force`, unpack may prompt before overwriting existing files.

## Security Notes

- Packing hides original directory layout inside the encrypted payload, but the outer ciphertext still leaks overall file size.
- Unpack should still be treated as a risky operation on untrusted input, even though the current implementation has explicit path identity and path-safety checks.
- The temporary decrypted archive is plaintext while it exists.
- Byte and storage needs are real operating assumptions. The structural limits bound archive metadata shape; they do not prove that the host has enough free memory or disk space.
