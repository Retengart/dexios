## Protected Wrapper

Dexios uses `Protected<T>` for in-memory secret values whose inner type implements `zeroize::Zeroize`.

Current contract:

- `Protected<T>` implements zeroize-on-drop by calling `Zeroize` when the wrapper is dropped.
- `fmt::Debug` is redacted and prints `[REDACTED]`.
- `Protected<T>` does not implement `fmt::Display`.
- `Protected<T>` has no blanket clone implementation and does not implement `Deref`.
- `Protected<T>` has no public direct exposure API.
- Secret access is closure-scoped through `with_exposed`, which keeps each exposure lifetime local and easy to audit.

The wrapper deliberately does not make secret copying convenient. If a caller needs bytes from a protected value, it must do the work inside a `with_exposed` closure and return only the non-secret result or a newly owned protected value.

This is an in-process owned-value handling contract. It reduces accidental
disclosure through debug output, clone paths, and long-lived references, but it
does not claim that every historical CPU, allocator, terminal, shell log, OS
swap, crash dump, or physical-media copy can be erased. It also does not make
generated passphrase terminal disclosure private after it has been printed.

Implementation and regression coverage:

- `dexios-core/src/protected.rs`
- `dexios-core/tests/protected.rs`
