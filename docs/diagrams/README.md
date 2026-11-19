# Diagrams

All public diagrams in this directory are **English-only**. The editable source
is `*.drawio`; the exported `*.png` and `*.svg` files are generated from it.
Keep the source and exports in sync when a component is added or renamed.

## Files

| Source | Purpose |
|---|---|
| `01-aegis-kraken.drawio` | End-to-end Aegis + Kraken architecture |
| `02-kraken-standalone.drawio` | Kraken standalone file-analysis pipeline |
| `03-kraken-to-aegis.drawio` | Kraken → Aegis event sequence |
| `04-command-queue.drawio` | At-least-once command queue |

## Export

Using the draw.io desktop CLI on Windows:

```bash
"/c/Program Files/draw.io/draw.io.exe" -x -f png -s 2 \
  -o docs/diagrams/01-aegis-kraken.png \
  docs/diagrams/01-aegis-kraken.drawio
```

Use `-f svg` for the SVG export. Generate the XML first with:

```bash
python scripts/generate_diagrams.py
```

## Conventions

- **Solid line:** control/data path that exists today.
- **Dashed line:** optional, external, retry, or failure/recovery path.
- **Green:** persisted state (Postgres, Redis, object store).
- **Purple:** Brain and Aegis control/UI.
- **Pink/red:** Kraken control/UI.
- **Amber:** external or optional component.
- No vendor logos, no marketing labels, no credentials.
- A new component must be added to `scripts/generate_diagrams.py` and to this
  table; do not hand-edit only the PNG.
