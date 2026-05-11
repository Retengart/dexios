## Performance Notes

Please note that performance is heavily dependent on your hardware - mostly disk speed. Dexios has had a *lot* of performance optimisations applied throughout the versions, but we're getting to the point where the main factor is disk speed.

We will continue to optimise Dexios where possible.

## Measured-Check Policy

Default changes to KDF cost, stream throughput behavior, pack/unpack memory
behavior, archive structural limits, or temp-space assumptions require a
measured-check run before the change is accepted.

Use the Phase 7 harness from the repository root:

```bash
scripts/measure_performance_gate.sh --scenario <name>
```

Available scenarios are:

- `kdf` for KDF cost regression evidence
- `stream` for representative encrypt/decrypt stream throughput evidence
- `pack-unpack` for representative pack/unpack memory and elapsed-time evidence
- `temp-space` for temporary workspace size evidence
- `all` for the full measured-check set

Record the command, fixture shape, platform, and summary result in release
notes or the phase summary. If a category is not applicable, record the reason
instead of silently omitting it.

The harness writes raw logs under `target/phase7-measurements/`. Do not commit
those logs as evergreen benchmark claims.

Structural archive limits are not proof that the host has enough free memory or
disk space. Temporary ZIP artifacts used by pack/unpack remain ordinary
plaintext temporary files while they exist.
