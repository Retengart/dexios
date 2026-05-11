## Delete Semantics

Dexios no longer exposes secure-erase behavior as a product feature.

Instead, the CLI offers plain delete-after-success flags:

- `encrypt --delete-input`
- `decrypt --delete-input`
- `unpack --delete-input`
- `pack --delete-source`

## Contract

The current contract is intentionally narrow:

1. complete the requested workflow successfully
2. commit every required staged output, detached header, extracted file, or metadata update
3. complete the requested hash calculation when hashing is enabled
4. delete the selected source inputs as a post-commit cleanup step

If the workflow fails, the source inputs remain in place.

Cleanup failures are reported after the output commit has already succeeded.
Dexios does not roll back committed outputs during this cleanup step.

## Why Secure Erase Was Removed

Overwrite passes are not a trustworthy abstraction on SSDs and other flash-backed storage. Dexios now prefers a simpler and more honest promise: delete sources after success, without claiming physical sanitization.

## Temporary Archives

`pack` and `unpack` still use temporary plaintext zip artifacts internally, but those artifacts are handled as ordinary temporary files rather than overwritten repeatedly before deletion.
