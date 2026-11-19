# Diagrams

All public diagrams in this directory are **English-only**. The editable source
is `*.drawio`; the exported `*.png` and `*.svg` files are generated from it.
Keep the source and exports in sync when a component is added or renamed.

## Visual system

The diagrams share one presentation, not the draw.io defaults:

- graphite canvas with a restrained, semantic palette (blue = Aegis, violet =
  Brain, emerald = persisted data, rose = Kraken, amber = external/optional);
- a document header with **DOC ID, version, date and owner**;
- a source footer and a one-line legend on every page;
- one canvas size (1600 × 1000) so the four pages read as a series;
- no vendor logos, screenshots, credentials or decorative clip art.

The version string and document IDs live in `scripts/generate_diagrams.py`.
Change them there, then re-export; do not edit a PNG or SVG by hand.

## Gallery

### 1. Aegis + Kraken — end-to-end flow

[![Aegis and Kraken end-to-end architecture](./01-aegis-kraken.png)](./01-aegis-kraken.png)

[Editable source](./01-aegis-kraken.drawio) · [SVG](./01-aegis-kraken.svg)

### 2. Kraken standalone — file analysis and deception

[![Kraken standalone file-analysis pipeline](./02-kraken-standalone.png)](./02-kraken-standalone.png)

[Editable source](./02-kraken-standalone.drawio) · [SVG](./02-kraken-standalone.svg)

### 3. Kraken → Aegis — signed event sequence

[![Kraken to Aegis event sequence](./03-kraken-to-aegis.png)](./03-kraken-to-aegis.png)

[Editable source](./03-kraken-to-aegis.drawio) · [SVG](./03-kraken-to-aegis.svg)

### 4. At-least-once command queue

[![At-least-once command queue](./04-command-queue.png)](./04-command-queue.png)

[Editable source](./04-command-queue.drawio) · [SVG](./04-command-queue.svg)

## Files

| Source | Purpose |
|---|---|
| `01-aegis-kraken.drawio` | End-to-end Aegis + Kraken architecture |
| `02-kraken-standalone.drawio` | Kraken standalone file-analysis pipeline |
| `03-kraken-to-aegis.drawio` | Kraken → Aegis event sequence |
| `04-command-queue.drawio` | At-least-once command queue |

## Export

Generate both the XML and the exports with the repository script:

```bash
python scripts/generate_diagrams.py --render
```

The script finds the draw.io desktop CLI in the common Windows, macOS and Linux
paths. For a manual export on Windows:

```bash
"/c/Program Files/draw.io/draw.io.exe" -x -f png -s 2 \
  -o docs/diagrams/01-aegis-kraken.png \
  docs/diagrams/01-aegis-kraken.drawio
```

Use `-f svg` for the SVG export. The PNG is exported at 2× (3202 × 2002) and
the SVG remains vector, so both are readable when GitHub scales the gallery.

## Conventions

- **Solid line:** control/data path that exists today.
- **Dashed line:** optional, external, retry, or failure/recovery path.
- **Blue:** Aegis endpoint/control plane.
- **Violet:** Brain and Aegis UI/API.
- **Emerald:** persisted state (Postgres, Redis, object store).
- **Rose:** Kraken control plane and sensors.
- **Amber:** external or optional component.
- **Slate:** neutral actor, boundary or note.
- A new component must be added to `scripts/generate_diagrams.py` and to this
  table; do not hand-edit only the PNG.
