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

Cleanup identity is evidence for this ordinary cleanup revalidation only. The
current workflows return processed-source cleanup evidence from the domain layer
instead of rebuilding cleanup authority from CLI path strings after commit.
Cleanup authority also requires complete commit evidence, requested hash
success, and final-auth evidence where the workflow produces a final
authentication receipt before publication.
Source replacement, final symlink substitution, hardlink alias surprises, and a
changed source tree are cleanup-refusal conditions; the source data is preserved
when refusal happens before deletion. This evidence is not secure erase,
physical sanitization, rollback, recovery, or broader deletion authority.

If the workflow fails, the source inputs remain in place.

Partial commit evidence is not cleanup authorization. Failed final
authentication, archive validation failure, failed requested hashes, and partial
commits leave cleanup blocked. If a linked filesystem transaction commits one
output and then fails on a later required artifact, Dexios reports the committed
artifact and the failed artifact, leaves cleanup blocked, and committed outputs
are not rolled back.

Detached payload/header publication follows the same rule. A detached encrypt or
pack operation is cleanup-eligible only when the payload and detached header from
the same linked operation both commit. Partial detached publication reports the committed and failed artifact state, source cleanup is denied after partial detached publication, and Dexios does not roll back committed artifacts or guarantee recovery.

Cleanup failures are reported after the output commit has already succeeded.
Dexios does not revert committed outputs during this cleanup step, and
committed outputs are not rolled back.

The deletion primitive remains ordinary filesystem deletion. Rust
`std::fs::remove_file` removes a path entry. In this contract, remove_file does not guarantee immediate physical deletion. Dexios therefore claims no secure erase, no physical sanitization, and no full power-failure proof for deleted inputs or temporary artifacts.

## Why Secure Erase Was Removed

Overwrite passes are not a trustworthy abstraction on SSDs and other flash-backed storage. Dexios now prefers a simpler and more honest promise: delete sources after success, without claiming physical sanitization.

## Temporary Archives

`pack` and `unpack` use Dexios-owned manifest-first archive payloads. Normal
operation no longer creates a full plaintext archive temporary file before or
after encryption. The current archive workflow has no full plaintext archive
temporary file.

The boundary is intentionally narrow:

- `pack` streams a `DXAR` manifest and ordered `DXBF` body frames directly into V1 encryption and then commits the encrypted staged output.
- `unpack` decrypts the manifest-first payload through authenticated V1 stream reading, validates the manifest, stages selected file bodies, observes final authentication, commits through storage transactions, and drops ordinary temporary/staged artifacts.
- Failure-path tests cover ordinary best effort drop/delete cleanup and no committed output after selected failures.

Plaintext exposure still exists while selected file bodies are being read,
staged, and committed. Dexios does not claim secure erase for temporary/staged
artifacts, does not claim sanitization, does not defend against another local
process with access to host temporary or output storage, and does not claim
resistance to forensic recovery.

The manifest-first archive behavior removes the old full plaintext archive
temporary file from normal operation. It does not remove ordinary plaintext file
content exposure during pack/unpack execution.
