## Performance Notes

Please note that performance is heavily dependent on your hardware - mostly disk speed. Dexios has had a *lot* of performance optimisations applied throughout the versions, but we're getting to the point where the main factor is disk speed.

We will continue to optimise Dexios where possible.

## Measured-Check Policy

Default changes to KDF cost, stream throughput behavior, pack/unpack memory
behavior, archive structural limits, or temp-space assumptions require a
measured-check run before the change is accepted.

Use the focused release gate from the repository root:

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

### Focused Threshold Checks

Timing and workspace-size thresholds are a focused release gate, not part of
`scripts/verify_phase_gate.sh`. Run it explicitly before changing KDF
parameters, stream behavior, archive packing behavior, unpack behavior, or
temp-space assumptions:

```bash
bash scripts/measure_performance_gate.sh --scenario all
```

The log records the scenario, UTC start time, `uname -a`, `rustc -Vv`,
`cargo -V`, CPU model when `/proc/cpuinfo` is available, and total memory when
`/proc/meminfo` is available. Record the hardware profile with the timing
result in the release notes or phase summary before using it as release
evidence.

For focused release checks, set a conservative local budget with either:

```bash
bash scripts/measure_performance_gate.sh --scenario all \
  --max-kdf-seconds <seconds> \
  --max-stream-encrypt-seconds <seconds> \
  --max-stream-decrypt-seconds <seconds> \
  --max-pack-seconds <seconds> \
  --max-unpack-seconds <seconds> \
  --max-temp-space-kib <kib>
```

or:

```bash
DEXIOS_KDF_MAX_SECONDS=<seconds> \
DEXIOS_STREAM_ENCRYPT_MAX_SECONDS=<seconds> \
DEXIOS_STREAM_DECRYPT_MAX_SECONDS=<seconds> \
DEXIOS_PACK_MAX_SECONDS=<seconds> \
DEXIOS_UNPACK_MAX_SECONDS=<seconds> \
DEXIOS_TEMP_SPACE_MAX_KIB=<kib> \
bash scripts/measure_performance_gate.sh --scenario all
```

The threshold names are intentionally explicit:

- KDF threshold: `--max-kdf-seconds` or `DEXIOS_KDF_MAX_SECONDS`
- stream encrypt threshold: `--max-stream-encrypt-seconds` or `DEXIOS_STREAM_ENCRYPT_MAX_SECONDS`
- stream decrypt threshold: `--max-stream-decrypt-seconds` or `DEXIOS_STREAM_DECRYPT_MAX_SECONDS`
- pack threshold: `--max-pack-seconds` or `DEXIOS_PACK_MAX_SECONDS`
- unpack threshold: `--max-unpack-seconds` or `DEXIOS_UNPACK_MAX_SECONDS`
- temp-space threshold: `--max-temp-space-kib` or `DEXIOS_TEMP_SPACE_MAX_KIB`

Elapsed-time thresholds are enforced for the matching timed operation.
The temp-space threshold is enforced against the maximum observed KiB under
the per-run measurement work root. Measurements that do not have a configured
threshold remain advisory evidence only.

Structural archive limits are not proof that the host has enough free memory or disk space. Capacity and temp-space measurements are best-effort release evidence, not a host-independent storage guarantee. They do not prove that unpack plaintext exposure is eliminated; current unpack still stages selected
file bodies as ordinary filesystem temporary/staged files before commit.
