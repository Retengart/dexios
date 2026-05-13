## Delete Semantics

Dexios no longer exposes secure-erase behavior as a product feature.

Instead, the CLI offers ordinary delete-after-success cleanup flags:

- `encrypt --delete-input`
- `decrypt --delete-input`
- `unpack --delete-input`
- `pack --delete-source`

## Contract

The current contract is intentionally narrow:

1. complete the requested workflow successfully
2. commit every required staged output, detached header, extracted file, or metadata update
3. complete the requested hash calculation when hashing is enabled
4. revalidate cleanup receipts, including changed cleanup identity checks
5. delete the selected source inputs as a post-commit cleanup step

If the workflow fails, the source inputs remain in place.

Partial commit evidence is not cleanup authorization. If a linked filesystem
transaction commits one output and then fails on a later required artifact,
Dexios reports the committed artifact and the failed artifact, leaves cleanup
blocked, and committed outputs are not rolled back.

Cleanup failures are reported after the output commit has already succeeded.
Dexios does not revert committed outputs during this cleanup step.

The deletion primitive remains ordinary filesystem deletion. Rust
`std::fs::remove_file` removes a path entry. In this contract, remove_file does not guarantee immediate physical deletion. Dexios therefore claims no secure erase, no physical sanitization, and no full power-failure proof for deleted inputs or temporary artifacts.

## Why Secure Erase Was Removed

Overwrite passes are not a trustworthy abstraction on SSDs and other flash-backed storage. Dexios now prefers a simpler and more honest promise: delete sources after success, without claiming physical sanitization.

## Temporary Archives

`pack` no longer writes a separate plaintext temporary ZIP artifact before
encryption. `unpack` still uses a decrypted temporary ZIP so it can validate
archive metadata, selected paths, duplicate names, and staged outputs before
committing extracted files.

The boundary is intentionally narrow:

- `pack` streams ZIP bytes directly into V1 encryption and then commits the encrypted staged output.
- `unpack` decrypts the encrypted payload into an ordinary plaintext temporary ZIP, validates archive metadata, stages selected files, commits through storage transactions, and drops the temporary artifact.
- Failure-path tests cover ordinary best effort drop/delete cleanup and no committed output after selected failures.

The unpack temporary ZIP artifact is plaintext exposure while it exists.
Dexios does not claim secure erase for it, does not claim sanitization, does
not defend against another local process with access to the host temporary
storage, and does not claim resistance to forensic recovery.

Pack-side plaintext temporary ZIP exposure was reduced in Phase 12.
Unpack-side plaintext temporary ZIP exposure remains.
