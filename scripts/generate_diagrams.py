#!/usr/bin/env python3
"""Generate the four Aegis/Kraken diagrams as editable draw.io files.

The public diagrams use one visual system: graphite canvas, restrained semantic
colors, a document header (ID, version, date, owner) and a source footer. The
editable source remains plain, uncompressed mxGraph XML so it can be opened in
draw.io and maintained without a generator-specific editor.

Usage:
    python scripts/generate_diagrams.py
    python scripts/generate_diagrams.py --render
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "diagrams"

VERSION = "4.3.0"
DATE = "2026-11-19"
OWNER = "Aegis Platform"
PAGE_W = 1600
PAGE_H = 1000

# Dark architecture palette. Fills are intentionally low-saturation; color is
# used to identify a domain, not to decorate every box.
BG = "#0A1220"
PANEL = "#0D1728"
BORDER = "#22324A"
TEXT = "#E6EEF8"
MUTED = "#8CA0B8"
FAINT = "#5E7188"
ACCENT = "#38BDF8"
EDGE = "#64748B"
WHITE = "#F8FAFC"

PALETTE = {
    "agent": ("#13243D", "#3B82F6", "#DBEAFE"),
    "brain": ("#201A3F", "#8B5CF6", "#EDE9FE"),
    "data": ("#112A27", "#10B981", "#D1FAE5"),
    "kraken": ("#2B1623", "#F43F5E", "#FFE4E6"),
    "external": ("#2A2111", "#F59E0B", "#FEF3C7"),
    "neutral": ("#182235", "#4B5D78", "#E2E8F0"),
    "process": ("#0F2A3C", "#06B6D4", "#CFFAFE"),
}


def _text_style(size: int, color: str, *, bold: bool = False,
                align: str = "left", valign: str = "middle") -> str:
    bold_attr = "fontStyle=1;" if bold else ""
    return (
        f"text;html=1;strokeColor=none;fillColor=none;align={align};"
        f"verticalAlign={valign};fontSize={size};fontColor={color};{bold_attr}"
        "whiteSpace=wrap;fontFamily=Helvetica;spacing=0;"
    )


def _text(cid: str, value: str, x: int, y: int, w: int, h: int,
          size: int, color: str, *, bold: bool = False,
          align: str = "left", valign: str = "middle") -> str:
    return (
        f'<mxCell id="{cid}" value="{escape(value, quote=False)}" '
        f'style="{_text_style(size, color, bold=bold, align=align, valign=valign)}" '
        f'vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" '
        f'height="{h}" as="geometry"/></mxCell>'
    )


def style(kind: str, *, dashed: bool = False, shape: str = "rounded=1;") -> str:
    fill, stroke, font = PALETTE[kind]
    dash = "dashed=1;dashPattern=8 6;" if dashed else ""
    return (
        f"{shape}whiteSpace=wrap;html=1;{dash}fillColor={fill};"
        f"strokeColor={stroke};strokeWidth=1.5;fontColor={font};fontSize=13;"
        "fontFamily=Helvetica;align=center;verticalAlign=middle;spacing=8;"
        "rounded=1;arcSize=10;"
    )


def container_style() -> str:
    return (
        "rounded=1;whiteSpace=wrap;html=1;dashed=1;dashPattern=3 7;"
        f"fillColor={PANEL};strokeColor={BORDER};strokeWidth=1;fontColor={FAINT};"
        "fontSize=11;fontStyle=1;align=left;verticalAlign=top;"
        "spacingLeft=18;spacingTop=12;fontFamily=Helvetica;"
    )


def node(nid: str, label: str, x: int, y: int, w: int, h: int,
         kind: str = "neutral", *, dashed: bool = False,
         shape: str = "rounded=1;") -> str:
    return (
        f'<mxCell id="{nid}" value="{escape(label, quote=False)}" '
        f'style="{style(kind, dashed=dashed, shape=shape)}" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/>'
        "</mxCell>"
    )


def container(nid: str, label: str, x: int, y: int, w: int, h: int) -> str:
    return (
        f'<mxCell id="{nid}" value="{escape(label, quote=False)}" '
        f'style="{container_style()}" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/>'
        "</mxCell>"
    )


def edge(eid: str, src: str, dst: str, label: str = "", *,
         dashed: bool = False, color: str = EDGE,
         exit_x: float = 1.0, exit_y: float = 0.5,
         entry_x: float = 0.0, entry_y: float = 0.5) -> str:
    dash = "dashed=1;dashPattern=8 6;" if dashed else ""
    return (
        f'<mxCell id="{eid}" value="{escape(label, quote=False)}" '
        "style=\"edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;"
        "jettySize=auto;html=1;endArrow=block;endFill=1;strokeWidth=1.8;"
        f"{dash}strokeColor={color};fontColor={MUTED};fontSize=10;"
        f"fontFamily=Helvetica;labelBackgroundColor={BG};"
        f'exitX={exit_x};exitY={exit_y};entryX={entry_x};entryY={entry_y};" '
        f'edge="1" parent="1" source="{src}" target="{dst}">'
        '<mxGeometry relative="1" as="geometry"/>'
        "</mxCell>"
    )


def line(eid: str, x1: int, y1: int, x2: int, y2: int, *,
         dashed: bool = True, color: str = BORDER, arrow: bool = False) -> str:
    dash = "dashed=1;dashPattern=4 7;" if dashed else ""
    end = "block" if arrow else "none"
    return (
        f'<mxCell id="{eid}" value="" style="endArrow={end};endFill=1;html=1;'
        "rounded=0;strokeWidth=1.5;"
        f"{dash}strokeColor={color};\" edge=\"1\" parent=\"1\">"
        f'<mxGeometry relative="1" as="geometry"><mxPoint x="{x1}" y="{y1}" '
        f'as="sourcePoint"/><mxPoint x="{x2}" y="{y2}" as="targetPoint"/>'
        "</mxGeometry></mxCell>"
    )


def swatch(cid: str, x: int, y: int, kind: str) -> str:
    fill, stroke, _ = PALETTE[kind]
    return (
        f'<mxCell id="{cid}" value="" style="rounded=0;html=1;fillColor={fill};'
        f'strokeColor={stroke};strokeWidth=1.5;" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="10" height="10" as="geometry"/>'
        "</mxCell>"
    )


def header(doc: str, title: str, subtitle: str) -> list[str]:
    return [
        f'<mxCell id="canvas" value="" style="rounded=0;html=1;fillColor={BG};'
        'strokeColor=none;" vertex="1" parent="1">'
        f'<mxGeometry x="0" y="0" width="{PAGE_W}" height="{PAGE_H}" as="geometry"/>'
        "</mxCell>",
        f'<mxCell id="top-rule" value="" style="rounded=0;html=1;fillColor={BORDER};'
        'strokeColor=none;" vertex="1" parent="1">'
        f'<mxGeometry x="40" y="124" width="{PAGE_W - 80}" height="1" as="geometry"/>'
        "</mxCell>",
        f'<mxCell id="accent" value="" style="rounded=1;html=1;fillColor={ACCENT};'
        'strokeColor=none;" vertex="1" parent="1">'
        '<mxGeometry x="40" y="30" width="3" height="72" as="geometry"/>'
        "</mxCell>",
        _text("eyebrow", "AEGIS PLATFORM  /  ARCHITECTURE", 58, 22, 650, 20,
              10, ACCENT, bold=True),
        _text("title", title, 58, 43, 1080, 40, 27, WHITE, bold=True),
        _text("subtitle", subtitle, 58, 85, 1080, 24, 12, MUTED),
        _text("meta", f"{doc}  /  04<br/><b>{VERSION}</b>  ·  {DATE}<br/>"
              f"Owner: {OWNER}", 1180, 31, 380, 65, 10, MUTED, align="right"),
    ]


def legend() -> list[str]:
    cells = [
        line("legend-solid", 40, 890, 78, 890, dashed=False, color=EDGE),
        _text("legend-solid-label", "implemented", 86, 878, 110, 24, 10, MUTED),
        line("legend-dash", 210, 890, 248, 890, dashed=True, color=EDGE),
        _text("legend-dash-label", "optional / recovery", 256, 878, 150, 24,
              10, MUTED),
        swatch("legend-agent", 430, 885, "agent"),
        _text("legend-agent-label", "Aegis", 446, 878, 60, 24, 10, MUTED),
        swatch("legend-brain", 520, 885, "brain"),
        _text("legend-brain-label", "Brain", 536, 878, 60, 24, 10, MUTED),
        swatch("legend-data", 610, 885, "data"),
        _text("legend-data-label", "data", 626, 878, 55, 24, 10, MUTED),
        swatch("legend-kraken", 700, 885, "kraken"),
        _text("legend-kraken-label", "Kraken", 716, 878, 65, 24, 10, MUTED),
        swatch("legend-external", 800, 885, "external"),
        _text("legend-external-label", "external", 816, 878, 70, 24, 10, MUTED),
        _text("legend-note", "One canvas. One vocabulary. Source in the repository.",
              1040, 878, 520, 24, 10, FAINT, align="right"),
    ]
    return cells


def footer(source: str) -> list[str]:
    return [
        f'<mxCell id="bottom-rule" value="" style="rounded=0;html=1;'
        f'fillColor={BORDER};strokeColor=none;" vertex="1" parent="1">'
        f'<mxGeometry x="40" y="932" width="{PAGE_W - 80}" height="1" as="geometry"/>'
        "</mxCell>",
        _text("footer-left", "AEGIS PLATFORM  ·  ARCHITECTURE SERIES",
              40, 944, 520, 20, 9, FAINT, bold=True),
        _text("footer-mid", "Controlled-pilot release candidate",
              700, 944, 280, 20, 9, FAINT, align="center"),
        _text("footer-source", f"Source: {source}", 1120, 944, 440, 20,
              9, FAINT, align="right"),
    ]


def page_xml(name: str, cells: list[str]) -> str:
    body = "\n".join(cells)
    return f'''<mxfile host="app.diagrams.net" modified="{DATE}T10:00:00.000Z" agent="aegis" version="24.7.17">
  <diagram id="{name}" name="{name}">
    <mxGraphModel dx="1600" dy="1000" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{PAGE_W}" pageHeight="{PAGE_H}" math="0" shadow="0" background="{BG}">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
{body}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
'''


def diagram_one() -> str:
    cells = header(
        "DOC-01",
        "Aegis + Kraken — end-to-end flow",
        "Two deployable services. The only Kraken → Aegis channel is the HMAC-signed HTTP outbox.",
    )
    cells += [
        container("aegis", "AEGIS  /  ENDPOINT SECURITY & SOC", 40, 148, 720, 690),
        container("kraken", "KRAKEN  /  DECEPTION & SANDBOX", 820, 148, 740, 690),
        node("agent", "aegis-agent (Go)<br/>endpoint · sensor · unified",
             80, 208, 240, 72, "agent"),
        node("link", "aegis-link (legacy)<br/>durable spool",
             80, 312, 240, 64, "agent", dashed=True),
        node("brain", "AEGIS BRAIN<br/><br/>ingest · auth<br/>Sigma · correlation<br/>"
             "alerts · incidents<br/>commands", 390, 202, 300, 218, "brain"),
        node("redis", "Redis<br/>command queues<br/>processing · DLQ",
             80, 468, 240, 66, "data"),
        node("pg", "Postgres<br/>events · alerts · incidents",
             390, 454, 300, 66, "data"),
        node("ui", "Aegis UI / API<br/>unified timeline",
             390, 556, 300, 66, "brain"),
        node("sensors", "Kraken sensors<br/>SSH · HTTP · FTP · SMB · RDP",
             860, 208, 250, 72, "kraken"),
        node("kapi", "Kraken API + UI<br/>sessions · campaigns · fleet",
             1180, 202, 300, 84, "kraken"),
        node("kdb", "Kraken DB<br/>events · hashed credentials",
             860, 330, 250, 64, "data"),
        node("obj", "Object store<br/>samples per job",
             1180, 322, 300, 64, "data"),
        node("outbox", "Signed outbox<br/>written with the event<br/>retry + HMAC",
             860, 438, 250, 64, "external"),
        node("broker", "Sandbox broker<br/>isolated network<br/>(detonation only)",
             1180, 438, 300, 64, "external"),
        node("kui", "Kraken UI<br/>operational data",
             860, 550, 250, 64, "kraken"),
        node("note", "No Docker socket in the web process.<br/>"
             "The sample is not executed by Brain.", 860, 700, 620, 58,
             "external", dashed=True),
        edge("e1", "agent", "brain", "HTTPS + mTLS / API key",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.3),
        edge("e2", "link", "brain", "legacy events", dashed=True,
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.75),
        edge("e3", "brain", "pg", "alert / incident",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e4", "pg", "ui", "query / state",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e5", "brain", "redis", "commands", color="#7C3AED",
             exit_x=0, exit_y=0.9, entry_x=0.5, entry_y=0),
        edge("e6", "sensors", "kapi", "",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("e7", "kapi", "kdb", "",
             exit_x=0, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e8", "kapi", "obj", "upload job",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e9", "obj", "broker", "sample", dashed=True, color="#D97706",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e10", "kdb", "outbox", "transaction + outbox",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e11", "outbox", "brain", "POST /ingest/kraken<br/>HMAC signature",
             dashed=True, color="#F43F5E", exit_x=0, exit_y=0.5,
             entry_x=1, entry_y=0.82),
    ]
    cells += legend()
    cells += footer("01-aegis-kraken.drawio  ·  English-only")
    return page_xml("Aegis-Kraken", cells)


def diagram_two() -> str:
    cells = header(
        "DOC-02",
        "Kraken standalone — file analysis & deception",
        "Kraken works without Aegis: upload, object storage, static analysis, optional detonation and report.",
    )
    cells += [
        container("kraken", "KRAKEN  /  STANDALONE ANALYSIS PIPELINE",
                  40, 148, 1520, 690),
        node("analyst", "Analyst", 70, 220, 150, 60, "neutral"),
        node("api", "Kraken API<br/>upload ZIP / file",
             280, 212, 220, 80, "kraken"),
        node("job", "Analysis job<br/>status = queued",
             560, 220, 210, 60, "data"),
        node("worker", "analysis_worker_loop<br/>Redis lease + recovery<br/>materialize",
             830, 208, 250, 80, "process"),
        node("static", "Static analysis<br/>IoC · ZIP · Sigma candidate",
             1130, 215, 270, 70, "process"),
        node("object", "Object store<br/>job_id / sha256",
             280, 360, 220, 66, "data"),
        node("decision", "DETONATION_URL<br/>configured?",
             1120, 370, 240, 100, "external", shape="rhombus;"),
        node("detonator", "HTTP detonator<br/>isolated VM / container",
             1400, 380, 150, 80, "external", dashed=True),
        node("merge", "Merge report<br/>process tree · DNS · MITRE",
             1110, 565, 300, 76, "process"),
        node("store", "Report + verdict<br/>DB / UI / export",
             830, 570, 230, 70, "data"),
        node("ui", "Kraken UI<br/>dashboard · report",
             560, 575, 210, 64, "kraken"),
        node("limits", "Without detonator: provenance = static-only<br/>"
             "explicit limitations, not empty arrays.", 70, 570, 420, 64,
             "external", dashed=True),
        edge("a1", "analyst", "api", "file",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a2", "api", "job", "202 + id",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a3", "api", "object", "stream + SHA-256",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("a4", "job", "worker", "claim",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a5", "worker", "static", "analyze",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a6", "static", "decision", "static report",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("a7", "decision", "detonator", "yes", dashed=True,
             color="#D97706", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a8", "detonator", "merge", "process_tree + dns_history",
             dashed=True, color="#D97706", exit_x=0.5, exit_y=1,
             entry_x=1, entry_y=0.5),
        edge("a9", "decision", "merge", "no → static-only", color="#64748B",
             exit_x=0.5, exit_y=1, entry_x=0.65, entry_y=0),
        edge("a10", "merge", "store", "completed",
             exit_x=0, exit_y=0.5, entry_x=1, entry_y=0.5),
        edge("a11", "store", "ui", "report",
             exit_x=0, exit_y=0.5, entry_x=1, entry_y=0.5),
    ]
    cells += legend()
    cells += footer("02-kraken-standalone.drawio  ·  English-only")
    return page_xml("Kraken-standalone", cells)


def diagram_three() -> str:
    cells = header(
        "DOC-03",
        "Kraken → Aegis — signed event sequence",
        "The event is persisted with the outbox in the same transaction; Brain may be unreachable and recover later.",
    )
    participants = [
        ("sensor", "Kraken sensor", 90, 190, "kraken"),
        ("kdb", "Kraken DB", 360, 190, "data"),
        ("outbox", "Kraken outbox", 630, 190, "external"),
        ("brain", "Brain ingest", 900, 190, "brain"),
        ("detect", "Sigma + correlation", 1170, 240, "brain"),
    ]
    for nid, label, x, w, kind in participants:
        cells.append(node(nid, label, x, 150, w, 62, kind))
    for nid, x in (("sensor", 185), ("kdb", 455), ("outbox", 725),
                   ("brain", 995), ("detect", 1290)):
        cells.append(line(f"life-{nid}", x, 212, x, 760, dashed=True,
                          color="#334155"))

    def msg(mid: str, y: int, x1: int, x2: int, label: str, *,
            dashed: bool = False) -> str:
        dash = "dashed=1;dashPattern=8 6;" if dashed else ""
        return (
            f'<mxCell id="{mid}" value="{escape(label, quote=False)}" '
            "style=\"endArrow=block;endFill=1;html=1;rounded=0;strokeWidth=1.8;"
            f"{dash}strokeColor={EDGE};fontColor=#B6C6D8;fontSize=10;"
            f"fontFamily=Helvetica;labelBackgroundColor={BG};\" edge=\"1\" "
            'parent="1"><mxGeometry relative="1" as="geometry">'
            f'<mxPoint x="{x1}" y="{y}" as="sourcePoint"/>'
            f'<mxPoint x="{x2}" y="{y}" as="targetPoint"/>'
            "</mxGeometry></mxCell>"
        )

    cells += [
        msg("m1", 270, 185, 455, "1. attack event"),
        msg("m2", 340, 455, 725, "2. INSERT event + outbox<br/>same transaction"),
        msg("m3", 420, 725, 995, "3. POST /api/v1/ingest/kraken<br/>"
            "X-Kraken-Signature: HMAC"),
        msg("m4", 500, 995, 1290, "4. parser + rules"),
        msg("m5", 570, 1290, 995, "5. alert / match"),
        msg("m6", 640, 995, 725, "6. 2xx → outbox sent", dashed=True),
        msg("m7", 710, 725, 455, "7. if Brain is down:<br/>"
            "outbox pending + backoff", dashed=True),
        node("result", "Brain persists alert / incident<br/>"
             "and shows it in the Aegis timeline", 900, 790, 430, 70, "brain"),
        line("result-arrow", 995, 760, 995, 790, dashed=False,
             color="#7C3AED", arrow=True),
        node("note", "No event is dropped if Brain is unreachable.<br/>"
             "Retries can duplicate: Brain deduplicates by event_id.",
             90, 790, 620, 64, "external", dashed=True),
    ]
    cells += legend()
    cells += footer("03-kraken-to-aegis.drawio  ·  English-only")
    return page_xml("Kraken-to-Aegis", cells)


def diagram_four() -> str:
    cells = header(
        "DOC-04",
        "At-least-once command queue",
        "Atomic claim, processing list, visibility timeout, idempotent ack, requeue and DLQ. At-least-once, not exactly-once.",
    )
    cells += [
        container("flow", "COMMAND PATH  /  BRAIN AND LINK", 40, 148, 1520, 650),
        node("producer", "Brain / playbook<br/>enqueue",
             80, 210, 210, 70, "brain"),
        node("queue", "Redis queue<br/>aegis:commands:&lt;agent&gt;",
             360, 210, 250, 70, "data"),
        node("claim", "Atomic claim<br/>LPOP + HSET + ZADD",
             680, 202, 270, 80, "process"),
        node("agent", "Agent<br/>executes the command",
             1020, 210, 230, 70, "agent"),
        node("processing", "Processing list<br/>delivery_id → raw",
             680, 350, 270, 70, "data"),
        node("ack", "Idempotent ack<br/>POST /commands/ack<br/>HDEL + ZREM",
             1020, 360, 230, 78, "brain"),
        node("reaper", "Reaper<br/>visibility timeout",
             360, 350, 250, 70, "external", dashed=True),
        node("retry", "LPUSH back to queue<br/>attempts + 1<br/>(new claim)",
             360, 510, 250, 64, "data"),
        node("dlq", "DLQ<br/>over max attempts",
             80, 510, 210, 64, "external", dashed=True),
        node("note", "Crash between execution and ack<br/>"
             "→ the command is redelivered.<br/>The action may run again.",
             80, 660, 500, 70, "external", dashed=True),
        node("note2", "Legacy Link uses the same contract<br/>"
             "and returns delivery_id to the agent.",
             680, 660, 450, 70, "external", dashed=True),
        edge("c1", "producer", "queue", "envelope",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("c2", "queue", "claim", "LPOP",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("c3", "claim", "agent", "command + delivery_id",
             exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("c4", "claim", "processing", "record",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("c5", "agent", "ack", "result",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("c6", "processing", "reaper", "timeout", dashed=True,
             color="#D97706", exit_x=0, exit_y=0.5,
             entry_x=1, entry_y=0.5),
        edge("c7", "reaper", "retry", "not acked",
             exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("c8", "reaper", "dlq", "", dashed=True, color="#DC2626",
             exit_x=0, exit_y=0.5, entry_x=0.5, entry_y=0),
    ]
    cells += legend()
    cells += footer("04-command-queue.drawio  ·  English-only")
    return page_xml("Command-queue", cells)


def find_drawio() -> str | None:
    candidates = [
        shutil.which("drawio"),
        r"C:\Program Files\draw.io\draw.io.exe",
        r"C:\Program Files\drawio\drawio.exe",
        "/Applications/draw.io.app/Contents/MacOS/draw.io",
        "/usr/bin/drawio",
        "/usr/local/bin/drawio",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def render(sources: list[Path]) -> None:
    executable = find_drawio()
    if not executable:
        raise SystemExit("draw.io CLI not found; install draw.io or export manually")
    for source in sources:
        for fmt in ("png", "svg"):
            output = source.with_suffix(f".{fmt}")
            command = [executable, "-x", "-f", fmt, "-s", "2", "-o",
                       str(output), str(source)]
            subprocess.run(command, check=True)
            print(f"rendered {output}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--render", action="store_true",
                        help="export PNG and SVG with the draw.io CLI")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "01-aegis-kraken.drawio": diagram_one(),
        "02-kraken-standalone.drawio": diagram_two(),
        "03-kraken-to-aegis.drawio": diagram_three(),
        "04-command-queue.drawio": diagram_four(),
    }
    sources = []
    for name, content in files.items():
        path = OUT / name
        path.write_text(content, encoding="utf-8")
        sources.append(path)
        print(f"written {path}")
    if args.render:
        render(sources)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
