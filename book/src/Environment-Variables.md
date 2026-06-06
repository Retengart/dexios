## Environment Variables

Dexios currently uses one documented environment variable for key input:

- `DEXIOS_KEY`

The CLI uses it only when you explicitly opt in with `--env-key`.

## Precedence

`DEXIOS_KEY` does **not** override explicit input supplied on the command line. If you pass `--keyfile` or `--auto`, those explicit options win. If you do not pass `--env-key`, an inherited `DEXIOS_KEY` is ignored and the CLI falls back to interactive entry when that workflow permits prompting.

In practice, the resolution order is:

1. explicit keyfile
2. explicit `--auto`
3. `DEXIOS_KEY` with `--env-key`
4. interactive entry

## Security Notes

Environment variables can be convenient for automation, but they are not ideal for every environment. Shell history, process launch tooling, CI logs, and host inspection policies may expose more than you expect. Use them deliberately and pass `--env-key` only on commands that are meant to consume `DEXIOS_KEY`.
