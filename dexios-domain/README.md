<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## Dexios-Domain

Dexios-Domain is the workflow layer between the CLI and `dexios-core`.

It handles higher-level operations such as:

- encrypt/decrypt request execution
- pack and unpack workflows
- secure erase helpers
- header dump/restore/strip
- V5 key manipulation
- storage abstraction for filesystem and tests

The CLI mostly validates user input and then dispatches these workflows through `dexios-domain`.

## Documentation

- crate API docs: <https://docs.rs/dexios-domain/latest/dexios_domain/>
- project book: <https://brxken128.github.io/dexios/>
