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

`pack` and `unpack` still use temporary plaintext zip artifacts internally, but those artifacts are handled as ordinary temporary files rather than overwritten repeatedly before deletion.

The boundary is intentionally narrow:

- `pack` writes source data into an ordinary plaintext temporary ZIP, then encrypts it and drops the temporary artifact.
- `unpack` decrypts the encrypted payload into an ordinary plaintext temporary ZIP, validates archive metadata, stages selected files, commits through storage transactions, and drops the temporary artifact.
- Failure-path tests cover ordinary best effort drop/delete cleanup and no committed output after selected failures.

These temporary ZIP artifacts are plaintext exposure while they exist. Dexios
does not claim secure erase for them, does not claim sanitization, does not
defend against another local process with access to the host temporary storage,
does not claim resistance to forensic recovery, and does not reduce plaintext
temporary ZIP exposure.
Plaintext temporary ZIP exposure remains, not reduced in Phase 11.
