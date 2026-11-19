#!/usr/bin/env python3
"""Generate the four Aegis/Kraken diagrams as editable draw.io files.

Plain, uncompressed mxGraph XML: open in the draw.io desktop app, edit, and
re-export with the CLI. Layouts are deliberately simple; the goal is a clean
explanation, not every possible call site.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "diagrams"

# English-only diagram labels. Keep this as the single translation map when a
# component is added or renamed; the source layout stays readable.
EN = {
    "AEGIS — endpoint security e SOC": "AEGIS — endpoint security & SOC",
    "KRAKEN — deception e sandbox": "KRAKEN — deception & sandbox",
    "aegis-agent Go<br/>endpoint · sensor · unified": "aegis-agent (Go)<br/>endpoint · sensor · unified",
    "aegis-link legacy<br/>spool durevole": "aegis-link (legacy)<br/>durable spool",
    "AEGIS BRAIN<br/><br/>ingest · auth<br/>Sigma · correlazione<br/>alert · incidenti<br/>comandi": "AEGIS BRAIN<br/><br/>ingest · auth<br/>Sigma · correlation<br/>alerts · incidents<br/>commands",
    "Postgres<br/>eventi · alert · incidenti": "Postgres<br/>events · alerts · incidents",
    "Redis<br/>code comandi<br/>processing · DLQ": "Redis<br/>command queues<br/>processing · DLQ",
    "Aegis UI / API<br/>timeline unificata": "Aegis UI / API<br/>unified timeline",
    "Sensori Kraken<br/>SSH · HTTP · FTP · SMB · RDP": "Kraken sensors<br/>SSH · HTTP · FTP · SMB · RDP",
    "Kraken API + UI<br/>sessioni · campagne · flotta": "Kraken API + UI<br/>sessions · campaigns · fleet",
    "Kraken DB<br/>eventi · credenziali hash": "Kraken DB<br/>events · hashed credentials",
    "Object store<br/>campioni per job": "Object store<br/>samples per job",
    "Sandbox broker<br/>rete isolata<br/>(solo detonazione)": "Sandbox broker<br/>isolated network<br/>(detonation only)",
    "Outbox firmata<br/>scritta con l'evento<br/>retry + HMAC": "Signed outbox<br/>written with the event<br/>retry + HMAC",
    "Kraken UI<br/>dati operativi": "Kraken UI<br/>operational data",
    "Nessun Docker socket nel processo web.<br/>Il sample non viene eseguito dal Brain.": "No Docker socket in the web process.<br/>The sample is not executed by Brain.",
    "HTTPS + mTLS/API key": "HTTPS + mTLS/API key",
    "eventi legacy": "legacy events",
    "alert / incidente": "alert / incident",
    "query / stato": "query / state",
    "comandi": "commands",
    "transazione + outbox": "transaction + outbox",
    "POST /ingest/kraken<br/>firma HMAC": "POST /ingest/kraken<br/>HMAC signature",
    "Kraken da solo — file analysis e deception": "Kraken standalone — file analysis & deception",
    "Kraken funziona senza Aegis: upload, object storage, analisi statica, detonazione opzionale e report.": "Kraken works without Aegis: upload, object storage, static analysis, optional detonation and report.",
    "KRAKEN standalone": "KRAKEN standalone",
    "Analista": "Analyst",
    "Kraken API<br/>upload ZIP / file": "Kraken API<br/>upload ZIP / file",
    "AnalysisJob<br/>status=queued": "AnalysisJob<br/>status=queued",
    "analysis_worker_loop<br/>lease Redis + recovery<br/>materialize": "analysis_worker_loop<br/>Redis lease + recovery<br/>materialize",
    "Object store<br/>job_id/sha256": "Object store<br/>job_id/sha256",
    "Analisi statica<br/>IoC · ZIP · Sigma candidate": "Static analysis<br/>IoC · ZIP · Sigma candidate",
    "DETONATION_URL<br/>configurato?": "DETONATION_URL<br/>configured?",
    "Detonatore HTTP<br/>VM/container isolato": "HTTP detonator<br/>isolated VM/container",
    "Merge report<br/>process tree · DNS · MITRE": "Merge report<br/>process tree · DNS · MITRE",
    "Report + verdict<br/>DB / UI / export": "Report + verdict<br/>DB / UI / export",
    "Kraken UI<br/>dashboard · report": "Kraken UI<br/>dashboard · report",
    "Senza detonatore: provenance=static-only<br/>limitations esplicite, non array vuoti.": "Without detonator: provenance=static-only<br/>explicit limitations, not empty arrays.",
    "file": "file",
    "202 + id": "202 + id",
    "stream + SHA-256": "stream + SHA-256",
    "claim": "claim",
    "analizza": "analyze",
    "report statico": "static report",
    "sì": "yes",
    "process_tree + dns_history": "process_tree + dns_history",
    "no → static-only": "no → static-only",
    "completed": "completed",
    "report": "report",
    "Come Aegis rileva un attacco avvenuto in Kraken": "How Aegis detects an attack that happened in Kraken",
    "L’evento è persistito con l’outbox nella stessa transazione; il Brain può essere irraggiungibile e recuperare dopo.": "The event is persisted with the outbox in the same transaction; Brain may be unreachable and recover later.",
    "Sensore Kraken": "Kraken sensor",
    "Kraken DB": "Kraken DB",
    "Outbox Kraken": "Kraken outbox",
    "Brain ingest": "Brain ingest",
    "Sigma + correlazione": "Sigma + correlation",
    "1. evento attacco": "1. attack event",
    "2. INSERT evento + outbox<br/>stessa transazione": "2. INSERT event + outbox<br/>same transaction",
    "3. POST /api/v1/ingest/kraken<br/>X-Kraken-Signature: HMAC": "3. POST /api/v1/ingest/kraken<br/>X-Kraken-Signature: HMAC",
    "4. parser + regole": "4. parser + rules",
    "5. alert / match": "5. alert / match",
    "6. 2xx → outbox sent": "6. 2xx → outbox sent",
    "7. se il Brain è down:<br/>outbox pending + backoff": "7. if Brain is down:<br/>outbox pending + backoff",
    "Brain persiste alert / incidente<br/>e lo mostra nella timeline Aegis": "Brain persists alert / incident<br/>and shows it in the Aegis timeline",
    "Nessun evento viene cancellato se il Brain è irraggiungibile.<br/>Il retry può duplicare: il Brain deduplica per event_id.": "No event is dropped if Brain is unreachable.<br/>Retries can duplicate: Brain deduplicates by event_id.",
    "Coda comandi at-least-once (Brain e Link)": "At-least-once command queue (Brain and Link)",
    "Claim atomico, processing list, visibility timeout, ack idempotente, requeue e DLQ. Garanzia at-least-once, non exactly-once.": "Atomic claim, processing list, visibility timeout, idempotent ack, requeue and DLQ. At-least-once, not exactly-once.",
    "Percorso del comando": "Command path",
    "Brain / playbook<br/>enqueue": "Brain / playbook<br/>enqueue",
    "Redis queue<br/>aegis:commands:&lt;agent&gt;": "Redis queue<br/>aegis:commands:&lt;agent&gt;",
    "Claim atomico<br/>LPOP + HSET + ZADD": "Atomic claim<br/>LPOP + HSET + ZADD",
    "Agente<br/>esegue il comando": "Agent<br/>executes the command",
    "Processing list<br/>delivery_id → raw": "Processing list<br/>delivery_id → raw",
    "Ack idempotente<br/>POST /commands/ack<br/>HDEL + ZREM": "Idempotent ack<br/>POST /commands/ack<br/>HDEL + ZREM",
    "Reaper<br/>visibility timeout": "Reaper<br/>visibility timeout",
    "LPUSH in coda<br/>attempts + 1<br/>(nuovo claim)": "LPUSH back to queue<br/>attempts + 1<br/>(new claim)",
    "DLQ<br/>oltre max attempts": "DLQ<br/>over max attempts",
    "Crash tra esecuzione e ack<br/>→ il comando viene riconsegnato.<br/>L’azione può essere ripetuta.": "Crash between execution and ack<br/>→ the command is redelivered.<br/>The action may run again.",
    "Link legacy usa lo stesso contratto<br/>e restituisce delivery_id all’agente.": "Legacy Link uses the same contract<br/>and returns delivery_id to the agent.",
    "envelope": "envelope",
    "LPOP": "LPOP",
    "comando + delivery_id": "command + delivery_id",
    "registra": "record",
    "esito": "result",
    "timeout": "timeout",
    "non ackato": "not acked",
}


def tr(value: str) -> str:
    return EN.get(value, value)


PALETTE = {
    "agent": ("#dbeafe", "#2563eb", "#1e3a8a"),
    "brain": ("#ede9fe", "#7c3aed", "#4c1d95"),
    "data": ("#dcfce7", "#16a34a", "#14532d"),
    "kraken": ("#ffe4e6", "#e11d48", "#881337"),
    "external": ("#fef3c7", "#d97706", "#78350f"),
    "neutral": ("#f1f5f9", "#475569", "#1e293b"),
    "process": ("#e0f2fe", "#0284c7", "#0c4a6e"),
}


def style(kind: str, *, dashed: bool = False, shape: str = "rounded=1;") -> str:
    fill, stroke, font = PALETTE[kind]
    dash = "dashed=1;" if dashed else ""
    return (
        f"{shape}whiteSpace=wrap;html=1;{dash}fillColor={fill};strokeColor={stroke};"
        f"fontColor={font};fontSize=13;align=center;verticalAlign=middle;spacing=6;"
    )


def container_style() -> str:
    return (
        "rounded=1;whiteSpace=wrap;html=1;dashed=1;dashPattern=6 6;"
        "fillColor=#f8fafc;strokeColor=#94a3b8;fontColor=#334155;"
        "fontSize=18;fontStyle=1;verticalAlign=top;spacingTop=12;"
    )


def node(nid: str, label: str, x: int, y: int, w: int, h: int, kind: str = "neutral",
         *, dashed: bool = False, shape: str = "rounded=1;") -> str:
    return (
        f'<mxCell id="{nid}" value="{escape(tr(label), quote=False)}" '
        f'style="{style(kind, dashed=dashed, shape=shape)}" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/>'
        "</mxCell>"
    )


def container(nid: str, label: str, x: int, y: int, w: int, h: int) -> str:
    return (
        f'<mxCell id="{nid}" value="{escape(tr(label), quote=False)}" '
        f'style="{container_style()}" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/>'
        "</mxCell>"
    )


def edge(eid: str, src: str, dst: str, label: str = "", *,
         dashed: bool = False, color: str = "#334155",
         exit_x: float = 1.0, exit_y: float = 0.5,
         entry_x: float = 0.0, entry_y: float = 0.5) -> str:
    dash = "dashed=1;" if dashed else ""
    return (
        f'<mxCell id="{eid}" value="{escape(tr(label), quote=False)}" '
        f'style="edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;'
        f'endArrow=block;endFill=1;strokeWidth=2;{dash}strokeColor={color};fontColor={color};'
        f'fontSize=11;labelBackgroundColor=#ffffff;'
        f'exitX={exit_x};exitY={exit_y};entryX={entry_x};entryY={entry_y};" '
        f'edge="1" parent="1" source="{src}" target="{dst}">'
        '<mxGeometry relative="1" as="geometry"/>'
        "</mxCell>"
    )


def line(eid: str, x1: int, y1: int, x2: int, y2: int, *,
         dashed: bool = True, color: str = "#94a3b8", arrow: bool = False) -> str:
    dash = "dashed=1;" if dashed else ""
    end = "block" if arrow else "none"
    return (
        f'<mxCell id="{eid}" value="" style="endArrow={end};endFill=1;html=1;rounded=0;'
        f'strokeWidth=2;{dash}strokeColor={color};" edge="1" parent="1">'
        f'<mxGeometry relative="1" as="geometry"><mxPoint x="{x1}" y="{y1}" as="sourcePoint"/>'
        f'<mxPoint x="{x2}" y="{y2}" as="targetPoint"/></mxGeometry></mxCell>'
    )


def page_xml(name: str, width: int, height: int, cells: list[str]) -> str:
    body = "\n".join(cells)
    return f'''<mxfile host="app.diagrams.net" modified="2026-11-19T10:00:00.000Z" agent="aegis" version="24.7.17">
  <diagram id="{name}" name="{name}">
    <mxGraphModel dx="1600" dy="1000" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{width}" pageHeight="{height}" math="0" shadow="0">
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
    cells = [
        f'<mxCell id="title" value="Aegis + Kraken — end-to-end flow" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=22;fontStyle=1;fontColor=#0f172a;" vertex="1" parent="1"><mxGeometry x="40" y="20" width="1000" height="36" as="geometry"/></mxCell>',
        f'<mxCell id="sub" value="Two separate services. The only Kraken → Aegis channel is the HMAC-signed HTTP outbox; no shared DB or process." style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=12;fontColor=#475569;" vertex="1" parent="1"><mxGeometry x="40" y="56" width="1300" height="24" as="geometry"/></mxCell>',
        container("aegis", "AEGIS — endpoint security e SOC", 40, 100, 720, 780),
        container("kraken", "KRAKEN — deception e sandbox", 820, 100, 740, 780),
        node("agent", "aegis-agent Go<br/>endpoint · sensor · unified", 80, 165, 240, 76, "agent"),
        node("link", "aegis-link legacy<br/>spool durevole", 80, 290, 240, 60, "agent", dashed=True),
        node("brain", "AEGIS BRAIN<br/><br/>ingest · auth<br/>Sigma · correlazione<br/>alert · incidenti<br/>comandi", 390, 165, 300, 235, "brain"),
        node("pg", "Postgres<br/>eventi · alert · incidenti", 390, 465, 300, 64, "data"),
        node("redis", "Redis<br/>code comandi<br/>processing · DLQ", 80, 465, 240, 70, "data"),
        node("ui", "Aegis UI / API<br/>timeline unificata", 390, 590, 300, 64, "brain"),
        node("sensors", "Sensori Kraken<br/>SSH · HTTP · FTP · SMB · RDP", 860, 165, 250, 80, "kraken"),
        node("kapi", "Kraken API + UI<br/>sessioni · campagne · flotta", 1180, 160, 300, 90, "kraken"),
        node("kdb", "Kraken DB<br/>eventi · credenziali hash", 860, 320, 250, 64, "data"),
        node("obj", "Object store<br/>campioni per job", 1180, 320, 300, 64, "data"),
        node("broker", "Sandbox broker<br/>rete isolata<br/>(solo detonazione)", 1180, 430, 300, 64, "external"),
        node("outbox", "Outbox firmata<br/>scritta con l'evento<br/>retry + HMAC", 860, 430, 250, 64, "external"),
        node("kui", "Kraken UI<br/>dati operativi", 860, 590, 250, 64, "kraken"),
        node("note", "No Docker socket in the web process.<br/>The sample is not executed by Brain.", 860, 710, 620, 60, "external", dashed=True),
        node("legend", "Legend: solid = control/data flow · dashed = optional or external", 80, 800, 620, 40, "neutral"),
        edge("e1", "agent", "brain", "HTTPS + mTLS/API key", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.3),
        edge("e2", "link", "brain", "eventi legacy", dashed=True, color="#64748b", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.75),
        edge("e3", "brain", "pg", "alert / incidente", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e4", "pg", "ui", "query / stato", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e5", "brain", "redis", "comandi", color="#7c3aed", exit_x=0, exit_y=0.9, entry_x=0.5, entry_y=0),
        edge("e6", "sensors", "kapi", "", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("e7", "kapi", "kdb", "", exit_x=0, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e8", "kapi", "obj", "upload job", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e9", "obj", "broker", "sample", dashed=True, color="#d97706", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e10", "kdb", "outbox", "transazione + outbox", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("e11", "outbox", "brain", "POST /ingest/kraken<br/>firma HMAC", dashed=True, color="#e11d48", exit_x=0, exit_y=0.5, entry_x=1, entry_y=0.8),
    ]
    return page_xml("Aegis-Kraken", 1600, 930, cells)


def diagram_two() -> str:
    cells = [
        f'<mxCell id="title" value="Kraken standalone — file analysis and deception" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=22;fontStyle=1;fontColor=#0f172a;" vertex="1" parent="1"><mxGeometry x="40" y="20" width="1000" height="36" as="geometry"/></mxCell>',
        f'<mxCell id="sub" value="Kraken works without Aegis: upload, object storage, static analysis, optional detonation and report." style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=12;fontColor=#475569;" vertex="1" parent="1"><mxGeometry x="40" y="56" width="1100" height="24" as="geometry"/></mxCell>',
        container("kraken", "KRAKEN standalone", 40, 100, 1320, 780),
        node("analyst", "Analista", 70, 175, 170, 60, "neutral"),
        node("api", "Kraken API<br/>upload ZIP / file", 300, 165, 250, 80, "kraken"),
        node("job", "AnalysisJob<br/>status=queued", 630, 165, 230, 60, "data"),
        node("worker", "analysis_worker_loop<br/>lease Redis + recovery<br/>materialize", 940, 155, 300, 80, "process"),
        node("obj", "Object store<br/>job_id/sha256", 300, 320, 250, 70, "data"),
        node("static", "Analisi statica<br/>IoC · ZIP · Sigma candidate", 940, 315, 300, 70, "process"),
        node("decision", "DETONATION_URL<br/>configurato?", 960, 445, 260, 120, "external", shape="rhombus;"),
        node("detonator", "Detonatore HTTP<br/>VM/container isolato", 1270, 455, 230, 90, "external", dashed=True),
        node("merge", "Merge report<br/>process tree · DNS · MITRE", 940, 640, 300, 76, "process"),
        node("store", "Report + verdict<br/>DB / UI / export", 630, 640, 230, 70, "data"),
        node("ui", "Kraken UI<br/>dashboard · report", 630, 760, 230, 64, "kraken"),
        node("limits", "Without detonator: provenance=static-only<br/>explicit limitations, not empty arrays.", 70, 670, 430, 70, "external", dashed=True),
        node("legend", "Legend: dashed = optional or external path", 70, 790, 430, 40, "neutral"),
        edge("a1", "analyst", "api", "file", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a2", "api", "job", "202 + id", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a3", "api", "obj", "stream + SHA-256", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("a4", "job", "worker", "claim", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a6", "worker", "static", "analizza", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("a7", "static", "decision", "report statico", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("a8", "decision", "detonator", "sì", dashed=True, color="#d97706", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("a9", "detonator", "merge", "process_tree + dns_history", dashed=True, color="#d97706", exit_x=0.5, exit_y=1, entry_x=1, entry_y=0.5),
        edge("a10", "decision", "merge", "no → static-only", color="#64748b", exit_x=0.5, exit_y=1, entry_x=0.65, entry_y=0),
        edge("a11", "merge", "store", "completed", exit_x=0, exit_y=0.5, entry_x=1, entry_y=0.5),
        edge("a12", "store", "ui", "report", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
    ]
    return page_xml("Kraken-standalone", 1400, 930, cells)


def diagram_three() -> str:
    cells = [
        f'<mxCell id="title" value="How Aegis detects an attack that happened in Kraken" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=22;fontStyle=1;fontColor=#0f172a;" vertex="1" parent="1"><mxGeometry x="40" y="20" width="1000" height="36" as="geometry"/></mxCell>',
        f'<mxCell id="sub" value="The event is persisted with the outbox in the same transaction; Brain may be unreachable and recover later." style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=12;fontColor=#475569;" vertex="1" parent="1"><mxGeometry x="40" y="56" width="1200" height="24" as="geometry"/></mxCell>',
        node("sensor", "Sensore Kraken", 70, 145, 190, 58, "kraken"),
        node("kdb", "Kraken DB", 340, 145, 190, 58, "data"),
        node("outbox", "Outbox Kraken", 610, 145, 190, 58, "external"),
        node("brain", "Brain ingest", 880, 145, 190, 58, "brain"),
        node("detect", "Sigma + correlazione", 1150, 145, 210, 58, "brain"),
    ]
    for nid, x in (("sensor", 165), ("kdb", 435), ("outbox", 705), ("brain", 975), ("detect", 1255)):
        cells.append(line(f"life-{nid}", x, 205, x, 690, dashed=True, color="#94a3b8"))

    def msg(mid: str, y: int, x1: int, x2: int, label: str, *, dashed: bool = False) -> str:
        dash = "dashed=1;" if dashed else ""
        return (
            f'<mxCell id="{mid}" value="{escape(tr(label), quote=False)}" '
            f'style="endArrow=block;endFill=1;html=1;rounded=0;strokeWidth=2;{dash}'
            f'strokeColor=#334155;fontColor=#334155;fontSize=11;labelBackgroundColor=#ffffff;" '
            f'edge="1" parent="1"><mxGeometry relative="1" as="geometry">'
            f'<mxPoint x="{x1}" y="{y}" as="sourcePoint"/><mxPoint x="{x2}" y="{y}" as="targetPoint"/>'
            "</mxGeometry></mxCell>"
        )

    cells += [
        msg("m1", 250, 165, 435, "1. evento attacco"),
        msg("m2", 320, 435, 705, "2. INSERT evento + outbox<br/>stessa transazione"),
        msg("m3", 400, 705, 975, "3. POST /api/v1/ingest/kraken<br/>X-Kraken-Signature: HMAC"),
        msg("m4", 480, 975, 1255, "4. parser + regole"),
        msg("m5", 550, 1255, 975, "5. alert / match"),
        msg("m6", 625, 975, 705, "6. 2xx → outbox sent", dashed=True),
        msg("m7", 690, 705, 435, "7. se il Brain è down:<br/>outbox pending + backoff", dashed=True),
        node("result", "Brain persiste alert / incidente<br/>e lo mostra nella timeline Aegis", 820, 760, 430, 70, "brain"),
        line("result-arrow", 975, 690, 975, 760, dashed=False, color="#7c3aed", arrow=True),
        node("note", "Nessun evento viene cancellato se il Brain è irraggiungibile.<br/>Il retry può duplicare: il Brain deduplica per event_id.", 70, 780, 600, 64, "external", dashed=True),
    ]
    return page_xml("Kraken-to-Aegis", 1450, 900, cells)


def diagram_four() -> str:
    cells = [
        f'<mxCell id="title" value="At-least-once command queue (Brain and Link)" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=22;fontStyle=1;fontColor=#0f172a;" vertex="1" parent="1"><mxGeometry x="40" y="20" width="1000" height="36" as="geometry"/></mxCell>',
        f'<mxCell id="sub" value="Atomic claim, processing list, visibility timeout, idempotent ack, requeue and DLQ. At-least-once, not exactly-once." style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=12;fontColor=#475569;" vertex="1" parent="1"><mxGeometry x="40" y="56" width="1250" height="24" as="geometry"/></mxCell>',
        container("flow", "Percorso del comando", 40, 100, 1280, 750),
        node("producer", "Brain / playbook<br/>enqueue", 80, 175, 210, 70, "brain"),
        node("queue", "Redis queue<br/>aegis:commands:&lt;agent&gt;", 360, 175, 250, 70, "data"),
        node("claim", "Claim atomico<br/>LPOP + HSET + ZADD", 680, 170, 270, 80, "process"),
        node("agent", "Agente<br/>esegue il comando", 1020, 175, 230, 70, "agent"),
        node("processing", "Processing list<br/>delivery_id → raw", 680, 320, 270, 70, "data"),
        node("ack", "Ack idempotente<br/>POST /commands/ack<br/>HDEL + ZREM", 1020, 340, 230, 78, "brain"),
        node("reaper", "Reaper<br/>visibility timeout", 360, 340, 250, 70, "external", dashed=True),
        node("retry", "LPUSH in coda<br/>attempts + 1<br/>(nuovo claim)", 360, 500, 250, 64, "data"),
        node("dlq", "DLQ<br/>oltre max attempts", 80, 500, 210, 64, "external", dashed=True),
        node("note", "Crash tra esecuzione e ack<br/>→ il comando viene riconsegnato.<br/>L’azione può essere ripetuta.", 80, 680, 500, 70, "external", dashed=True),
        node("note2", "Legacy Link uses the same contract<br/>and returns delivery_id to the agent.", 680, 680, 450, 70, "external", dashed=True),
        node("legend", "Legend: dashed = failure/recovery path", 80, 790, 500, 40, "neutral"),
        edge("c1", "producer", "queue", "envelope", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("c2", "queue", "claim", "LPOP", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("c3", "claim", "agent", "comando + delivery_id", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5),
        edge("c4", "claim", "processing", "registra", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("c5", "agent", "ack", "esito", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("c6", "processing", "reaper", "timeout", dashed=True, color="#d97706", exit_x=0, exit_y=0.5, entry_x=1, entry_y=0.5),
        edge("c7", "reaper", "retry", "non ackato", exit_x=0.5, exit_y=1, entry_x=0.5, entry_y=0),
        edge("c8", "reaper", "dlq", "", dashed=True, color="#dc2626", exit_x=0, exit_y=0.5, entry_x=0.5, entry_y=0),
    ]
    return page_xml("Command-queue", 1400, 900, cells)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "01-aegis-kraken.drawio": diagram_one(),
        "02-kraken-standalone.drawio": diagram_two(),
        "03-kraken-to-aegis.drawio": diagram_three(),
        "04-command-queue.drawio": diagram_four(),
    }
    for name, content in files.items():
        (OUT / name).write_text(content, encoding="utf-8")
        print(f"written {OUT / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
