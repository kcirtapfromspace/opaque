# Demos

The repository includes short terminal demos used in `README.md`:

- `assets/demos/quickstart.gif`
- `assets/demos/sandbox-exec.gif`

They are recorded in a throwaway temp `HOME`/`XDG_RUNTIME_DIR` to avoid touching your real `~/.opaque` state and to ensure no secrets are involved.

## Regenerate

Prereqs:

- `asciinema` (record)
- `agg` (convert asciinema cast -> GIF)

Run:

```bash
./scripts/record_demos.sh
```

This will (re)build release binaries, record casts, and write GIFs under `assets/demos/`.

