## Checksums

Dexios uses `BLAKE3` for its optional checksum output and standalone hashing mode.

This checksum output is **not** the primary integrity mechanism for encrypted files. Dexios already uses authenticated encryption and header AAD validation. Checksums are mainly useful for out-of-band comparisons, archival workflows, and manual verification.

## `-H/--hash`

The CLI can print a BLAKE3 hash of the encrypted input file after an operation:

- after `encrypt`
- after `decrypt`
- after `pack`
- after `unpack`

For decrypting and unpacking, the hash is still computed over the encrypted input file, not over the decrypted output.

## Standalone Hashing Mode

You can hash any file directly:

```bash
dexios hash file.enc
```

Multiple files are supported:

```bash
dexios hash one.enc two.enc
```

## Notes

- `BLAKE3` is the only hashing algorithm exposed by the CLI checksum mode.
- Historical checksum algorithms used by older Dexios releases are not relevant to the current CLI surface except for compatibility discussions.

## Performance

Checksum throughput is usually fast enough that storage and file I/O dominate runtime for normal workflows. As with the rest of Dexios, modern performance is usually limited more by disk speed than by the checksum algorithm itself.
