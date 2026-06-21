## Environment Variables

Dexios does not read key material from environment variables.

This is intentional. Environment variables are frequently captured by shell history, process launch tooling, CI logs, crash reports, and host inspection policies before an application can scrub them. Dexios avoids that class of leakage by accepting automation keys through keyfiles instead.

For noninteractive automation, use one of these forms:

```bash
dexios encrypt --keyfile keyfile secret.txt secret.enc
```

```bash
printf '%s' 'correct horse battery staple' | dexios encrypt --keyfile - secret.txt secret.enc
```

## Precedence

The key-source resolution order is:

1. explicit keyfile
2. explicit `--auto`
3. interactive entry
