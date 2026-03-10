# Dexios-Domain

`dexios-domain` is the workflow layer between the CLI and `dexios-core`.

It owns the higher-level operations that are awkward to model as raw primitives alone, including:

- V1 file encryption and decryption requests
- pack and unpack workflows
- header dump/restore/strip operations
- V1 key manipulation
- storage abstractions for real files and tests

The CLI mostly constructs request objects, then delegates the actual work to `dexios-domain`.
