## Performance Notes

Please note that performance is heavily dependent on your hardware - mostly disk speed. Dexios has had a *lot* of performance optimisations applied throughout the versions, but we're getting to the point where the main factor is disk speed.

We will continue to optimise Dexios where possible.

## Measured-Check Policy

Default changes to KDF cost, stream throughput behavior, pack/unpack memory
behavior, archive structural limits, or temp-space assumptions require a
measured-check run before the change is accepted.

Use the measurement harness from the repository root:

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

### Focused KDF checks

KDF timing is a focused release check, not part of
`scripts/verify_phase_gate.sh`. Run it explicitly before changing KDF
parameters or dependency feature policy:

```bash
bash scripts/measure_performance_gate.sh --scenario kdf
```

The log records the scenario, UTC start time, `uname -a`, `rustc -Vv`,
`cargo -V`, CPU model when `/proc/cpuinfo` is available, and total memory when
`/proc/meminfo` is available. Record the hardware profile with the timing
result in the release notes or phase summary before using it as KDF evidence.

For focused release checks, set a conservative local budget with either:

```bash
bash scripts/measure_performance_gate.sh --scenario kdf --max-kdf-seconds <seconds>
```

or:

```bash
DEXIOS_KDF_MAX_SECONDS=<seconds> bash scripts/measure_performance_gate.sh --scenario kdf
```

This threshold applies only to the `kdf` scenario. Stream, pack/unpack, and
temp-space scenarios continue to record measurements without KDF elapsed-time
enforcement.

Structural archive limits are not proof that the host has enough free memory or
disk space. Temporary ZIP artifacts used by pack/unpack remain ordinary
plaintext temporary files while they exist.
