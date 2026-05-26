## Directory Packing

Current `pack` and `unpack` use Dexios-owned manifest-first archive payloads
inside the normal canonical V1 encrypted payload stream. The archive payload
starts with a `DXAR` manifest and stores file contents as ordered `DXBF` body
frames.

ZIP bytes, ZIP central-directory metadata, ZIP crate types, compression
selectors, and broad metadata knobs are not canonical V1 archive format surface.
Normal operation no longer creates a full plaintext archive temporary file.
The current archive workflow has no full plaintext archive temporary file.

## Current CLI Behavior

The current CLI accepts one or more input directories:

```bash
dexios pack photos/ archive.enc
```

```bash
dexios pack photos/ videos/ archive.enc
```

`--recursive` is retained for compatibility, but recursive traversal is already
the default behavior.

Compression is not user-configurable. Pack uses Dexios-owned manifest-first
archive framing with a fixed archive policy.

## Current Archive Creation

The current implementation:

1. validates the input directories
2. derives unique archive root names for the provided inputs
3. excludes the output file and detached header path from being re-packed
4. materializes the directory and file entry list in memory
5. checks the shared `ArchiveLimits` structural policy
6. writes a `DXAR` manifest and ordered `DXBF` body frames through the
   manifest-first archive writer
7. encrypts those archive bytes using the same canonical V1 stream encryption
   path used for normal files
8. commits the final encrypted output and detached header through pair-aware
   staged storage transaction semantics

Pack registers input directories, requested outputs, and generated output/header
paths through the shared storage identity graph. Existing path roles reject final
symlinks and symlinked parent prefixes before canonicalization, and generated
outputs are checked against source roots before archive bytes are written.
Delete-after-success cleanup for pack is bound to processed-source cleanup
evidence captured for the selected source roots. Directory cleanup revalidates
the root identity and the processed tree; a changed source tree is reported as
cleanup refusal rather than deleting new user data.

Pack still materializes the entry list and streams file contents through the
archive writer, but it does not create a separate full plaintext archive
temporary file before encryption.

Storage transaction semantics here mean same-directory temporary files and
staged flush/sync/fd-relative final placement. Dexios writes staged outputs,
flushes them, calls `File::sync_all`, and then finalizes Unix targets through
opened parent directories: `linkat` for create-new output and `renameat` for
replace-at-commit output. Linked commits prepare every staged output before any
output is persisted. If a later persist fails after an earlier artifact was
committed, Dexios reports partial commit evidence; committed outputs are not
rolled back.

For detached pack output, pair-aware detached publication means the generated
payload and generated detached header must both commit from the same linked
operation before cleanup can run. Partial detached publication reports the
committed and failed artifact state, source cleanup is denied after partial
detached publication, and committed artifacts remain visible.

Dexios syncs staged file contents and file metadata before persist, but it does
not claim portable parent-directory durability across every filesystem or
platform. This is no full power-failure proof.

The archive is always written with the Dexios-owned fixed archive policy. The
public archive contract intentionally stays small: archive path plus
file/directory distinction. Dexios does not currently guarantee preservation of
permissions, timestamps, archive extra fields, symlinks, extended attributes, or
other filesystem metadata as stable compatibility behavior.

## Current Structural Limits

Pack and unpack share the same `ArchiveLimits` defaults:

- maximum archive entries: `100000`
- maximum normalized archive path bytes: `4096`
- maximum normalized archive path depth: `64`

Pack checks these limits while materializing source entries and before archive
writing begins. Unpack checks entry count before metadata scanning, and checks
each normalized archive path before prompts, staging, or writes.

These are structural limits, not storage-capacity guarantees. Large directory
trees and archives still require enough memory and output space for materialized
entry lists, encrypted output, and extracted files. Unpack also requires
temporary/staged space for selected extracted file bodies. Dexios uses
best-effort capacity pressure reporting where the platform preserves the source
error, but it does not prove portable free space before starting the workflow.
Structural limits are metadata bounds; they do not prove that the host has enough free memory or disk space.

The current unpack model is bounded by indexing: unpack pre-scans manifest
metadata, collision sets, and selected targets before transaction commit.

## Canonical Manifest-First Framing

Canonical V1 reserves archive payload structure for Dexios-owned
manifest-first framing rather than ZIP implementation surface. The shared core
payload contract distinguishes:

- raw-file payloads using LE31 stream framing
- manifest archive payloads using manifest-first framing

The manifest-first framing starts with a `DXAR` manifest. The manifest records
the ordered file/directory entries, normalized path bytes, entry kind, and file
body lengths. File bodies then follow as ordered `DXBF` body frames.

The core framing enforces structural limit checks for manifest entry count,
normalized path byte length, body frame length, missing body frames, duplicate
body frames, body-frame length mismatch, and ordered body-frame rules. Body
frames must appear in manifest file-entry order; a body frame for a directory is
rejected.

ZIP bytes, ZIP central-directory metadata, ZIP crate types, compression
selectors, and broad metadata knobs are not canonical V1 archive format surface.
They are also not canonical V1 surface.
Domain policy owns path normalization, traversal rejection, duplicate and prefix
collision checks, selected-output filtering, target revalidation, and staged
transaction commit.

## Current Unpacking

The current unpack flow is stricter than the historical docs:

The public Rust API constructs unpack work through checked `UnpackIntent` state
rather than raw request fields. The CLI passes the raw archive path and optional
detached-header path into this domain construction; the domain registers those
sources as `Input` and `DetachedHeader`, validates them in the shared identity
graph, and opens checked sources through
`FileStorage::read_resolved_existing_no_follow`. On Unix, that boundary uses
`O_NOFOLLOW` plus opened-file identity recheck; non-Unix behavior is limited by platform identity APIs and available tests. The CLI still owns prompting and
selected archive entries; the domain layer keeps archive validation, output-root
and target path identity checks, staging, and transaction commit behavior.

1. construct checked unpack intent from the raw archive path, optional
   detached-header path, and requested output root
2. register and open archive/header sources through checked no-follow storage
   reads
3. decrypt the packed file through the authenticated V1 stream reader
4. read and validate the `DXAR` manifest before selected body staging
5. normalize every archive path before writing anything to disk
6. enforce the shared `ArchiveLimits` entry count, path byte, and path depth
   policy
7. reject traversal attempts, unsafe archive names, duplicate normalized paths,
   and prefix collisions
8. reject unsafe symlink-based output escapes through the storage layer
9. run overwrite prompts only after the structural validation pass succeeds
10. stage selected extracted file bodies under the requested output root while
   checking ordered `DXBF` body frames
11. observe final stream authentication before committing outputs
12. revalidate selected file targets near staging and before commit
13. create selected directories after final authentication, tracking only
    directories created by the current unpack pass
14. commit the extracted files through storage transaction semantics
15. clean up ordinary temporary/staged artifacts

If the CLI is not run with `--force`, unpack may prompt before overwriting
existing files.

If the first selected file commit fails after selected directories were created, unpack best-effort removes directories created by the current post-final-auth directory pass before first selected file commit. Pre-existing directories are preserved. After `TransactionError::PartialCommit`, committed file artifacts are not rolled back.

## Security Notes

- Packing hides original directory layout inside the encrypted payload, but the
  outer ciphertext still leaks overall file size.
- Unpack should still be treated as a risky operation on untrusted input.
  Current source/header identity and output path checks reject final symlinks,
  symlinked parent prefixes, and path aliases through the shared storage layer,
  but they are not a sandbox.
- Normal operation no longer creates a full plaintext archive temporary file.
- The current archive workflow has no full plaintext archive temporary file.
- Unpack-side plaintext exposure is scoped to selected staged file bodies and
  ordinary filesystem temporary/staged files while the workflow is running.
- Temporary/staged cleanup is ordinary filesystem cleanup, not secure erase.
- Checked unpack construction makes the public API harder to bypass; it does
  not add a capacity proof or physical sanitization.
- Byte and storage needs are real operating assumptions. The structural limits
  bound archive metadata shape; they do not prove that the host has enough free
  memory or disk space.
- capacity pressure messages are best-effort diagnostics from preserved IO
  sources; they are not a portable capacity preflight.
- Delete-source cleanup after successful pack or unpack remains ordinary
  delete-after-success cleanup, not sanitization.
