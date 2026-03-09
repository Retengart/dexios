# Dexios-Domain

`dexios-domain` is the workflow layer between the CLI and `dexios-core`.

It owns the higher-level operations that are awkward to model as raw primitives alone, including:

- file encryption and decryption requests
- pack and unpack workflows
- secure erase helpers
- header dump/restore/strip operations
- V5 key manipulation
- storage abstractions for real files and tests

The CLI mostly constructs request objects, then delegates the actual work to `dexios-domain`.
