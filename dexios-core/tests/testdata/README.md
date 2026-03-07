# KDF Testdata Provenance

This directory contains checked-in reference vectors for KDF assurance tests in
`dexios-core/tests/key_derivation.rs`.

These vectors are intended to prove external correctness of Dexios KDF behavior,
not Dexios file-format backward compatibility. Dexios compatibility fixtures
must stay in their existing domain-level tests and remain separate from these
reference vectors.

## Source Policy

- Argon2id vectors come from an independent Python path:
  `argon2-cffi` 25.1.0 using `argon2.low_level.hash_secret_raw(Type.ID)`.
- Balloon vectors come from an independent Python implementation:
  `https://github.com/nachonavarro/balloon-hashing` at commit
  `8e28a7822113f1e8ef56b175550210c1a8e36c1a`, adapted locally to use Python
  `blake3` 1.0.8 as the hash primitive with `delta=3`.

Why these sources count as independent for Dexios assurance:

- `argon2-cffi` is outside Dexios and outside the RustCrypto `argon2` crate used by
  production code. It exercises a separate Python binding path over the reference
  Argon2 implementation instead of Dexios’s Rust wrapper path.
- `balloon-hashing` is a separate Python implementation from a different codebase
  than Dexios and RustCrypto. The local adaptation only swaps in Python `blake3`
  as the hash primitive so the algorithm matches Dexios’s BLAKE3-Balloon choice;
  the control flow and mixing logic still come from that independent implementation.

## Generation Notes

The checked-in vectors were generated on 2026-03-07 with:

- password: `test-password`
- 16-byte salts filled with the version number (`0x01` for V1 through `0x05` for V5)
- Dexios KDF parameter sets for each supported version

Argon2id parameter mapping:

- V1: memory 8192 KiB, time 8, parallelism 4, output length 32
- V2: memory 262144 KiB, time 8, parallelism 4, output length 32
- V3: memory 262144 KiB, time 10, parallelism 4, output length 32

Balloon parameter mapping:

- V4: space 262144, time 1, delta 3
- V5: space 278528, time 1, delta 3

## Exact Generation Recipe

Argon2id vectors were generated with a one-shot Python command equivalent to:

```bash
python3 - <<'PY'
from argon2.low_level import hash_secret_raw, Type

password = b"test-password"
cases = [
    ("V1", 8192, 8, 4, 1),
    ("V2", 262144, 8, 4, 2),
    ("V3", 262144, 10, 4, 3),
]

for version, mem_kib, time_cost, parallelism, salt_byte in cases:
    output = hash_secret_raw(
        password,
        bytes([salt_byte]) * 16,
        time_cost=time_cost,
        memory_cost=mem_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )
    print(version, output.hex())
PY
```

Balloon vectors were generated with a one-shot Python command equivalent to:

```bash
python3 - <<'PY'
import blake3

def hash_func(*args):
    data = b""
    for arg in args:
        if type(arg) is int:
            data += arg.to_bytes(8, "little")
        elif type(arg) is str:
            data += arg.encode("utf-8")
        else:
            data += arg
    return blake3.blake3(data).digest()

def balloon(password: str, salt: bytes, space_cost: int, time_cost: int, delta: int = 3) -> bytes:
    buf = [hash_func(0, password, salt)]
    cnt = 1
    for s in range(1, space_cost):
        buf.append(hash_func(cnt, buf[s - 1]))
        cnt += 1
    for t in range(time_cost):
        for s in range(space_cost):
            buf[s] = hash_func(cnt, buf[s - 1], buf[s])
            cnt += 1
            for i in range(delta):
                idx_block = hash_func(t, s, i)
                other = int.from_bytes(hash_func(cnt, salt, idx_block), "little") % space_cost
                cnt += 1
                buf[s] = hash_func(cnt, buf[s], buf[other])
                cnt += 1
    return buf[-1]

cases = [
    ("V4", 262144, 1, 4),
    ("V5", 278528, 1, 5),
]

for version, space_cost, time_cost, salt_byte in cases:
    output = balloon("test-password", bytes([salt_byte]) * 16, space_cost, time_cost)
    print(version, output.hex())
PY
```

## Update Policy

- Do not regenerate vectors from the current Dexios implementation and then
  treat them as independent truth.
- Do not update vectors casually just to make tests pass.
- Any vector change must explain:
  - why the previous provenance is no longer acceptable
  - what independent source produced the new values
  - how to reproduce the generation path manually

## Why These Vectors Exist

These vectors catch:

- KDF parameter drift
- version-mapping drift
- salt or password handling regressions
- unexpected upstream behavior changes

They do not replace Dexios backward-compatibility fixtures.
