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
erase, sanitization, local temp-storage isolation, or recovery protection after
host storage inspection.

Storage transaction semantics here mean same-directory temporary files and
staged flush/sync/persist before final placement. Dexios writes staged outputs,
flushes them, calls `File::sync_all`, and then uses
`tempfile::NamedTempFile::persist` or `persist_noclobber` according to the
overwrite policy. Linked commits prepare every staged output before any output
is persisted. If a later persist fails after an earlier artifact was committed,
Dexios reports partial commit evidence; committed outputs are not rolled back.

Dexios syncs staged file contents and file metadata before persist, but it does
not claim portable parent-directory durability across every filesystem or
platform. This is no full power-failure proof.

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

The public Rust API constructs unpack work through checked `UnpackIntent` state
rather than raw request fields. The CLI still owns prompting and selected input
paths; the domain layer keeps archive validation, path identity checks, staging,
and transaction commit behavior.

1. construct checked unpack intent from opened input/header entries and the requested output root
2. decrypt the packed file into a temporary zip artifact
3. normalize every archive path before writing anything to disk
4. enforce the shared `ArchiveLimits` entry count, path byte, and path depth policy
5. reject traversal attempts, unsafe ZIP names, duplicate normalized paths, and prefix collisions
6. reject unsafe symlink-based output escapes through the storage layer
7. run overwrite prompts only after the structural validation pass succeeds
8. revalidate selected file targets near staging
9. stage selected extracted files under the requested output root
10. commit the extracted files through storage transaction semantics
11. clean up the temporary archive

If the CLI is not run with `--force`, unpack may prompt before overwriting existing files.

## Security Notes

- Packing hides original directory layout inside the encrypted payload, but the outer ciphertext still leaks overall file size.
- Unpack should still be treated as a risky operation on untrusted input, even though the current implementation has explicit path identity and path-safety checks.
- The temporary decrypted archive is plaintext while it exists.
- Checked unpack construction makes the public API harder to bypass; it does not reduce plaintext temporary ZIP exposure or add a capacity proof.
- Plaintext temporary ZIP exposure remains, not reduced in Phase 11.
- Byte and storage needs are real operating assumptions. The structural limits bound archive metadata shape; they do not prove that the host has enough free memory or disk space.
- Delete-source cleanup after successful pack or unpack remains ordinary delete-after-success cleanup, not sanitization.
