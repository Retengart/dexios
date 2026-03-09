## Environment Variables

Dexios currently uses one documented environment variable for key input:

- `DEXIOS_KEY`

If it is set, the CLI can use it as a fallback key source.

## Precedence

`DEXIOS_KEY` does **not** override explicit input supplied on the command line. If you pass `--keyfile` or `--auto`, those explicit options win.

In practice, the resolution order is:

1. explicit keyfile
2. explicit `--auto`
3. `DEXIOS_KEY`
4. interactive entry

## Security Notes

Environment variables can be convenient for automation, but they are not ideal for every environment. Shell history, process launch tooling, CI logs, and host inspection policies may expose more than you expect. Use them deliberately.
