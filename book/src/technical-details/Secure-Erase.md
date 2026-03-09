## Secure Erase

Dexios implements a best-effort overwrite-and-delete workflow. It should not be treated as a guarantee of physical erasure, especially on SSDs and other flash-backed storage.

## Current Erase Flow

For a normal file erase request, Dexios:

1. opens the file for overwriting
2. performs the requested number of random overwrite passes
3. performs one final zero pass
4. truncates and removes the file through the storage layer

The user-facing default is **1 random pass** followed by the zero pass.

You can request a different pass count with:

```bash
dexios erase --passes=3 file.txt
```

or through `--erase[=N]` on encrypt/decrypt/unpack workflows.

## Directories

When a directory is erased through the CLI workflow, Dexios traverses it, erases regular files, and then removes the directory tree.

## Limits

- SSDs and flash media may retain older data because of wear leveling and controller behavior.
- More passes increase I/O cost and media wear.
- Dexios does not claim certified sanitization behavior.

## Temporary Archives

The current implementation also uses the overwrite helper for temporary plaintext zip artifacts:

- `pack` currently cleans its temporary archive with **2 random passes** plus the final zero pass
- `unpack` currently cleans its temporary archive with **1 random pass** plus the final zero pass

Those are implementation details of the current release, not long-term format guarantees.
