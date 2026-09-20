#!/usr/bin/env python3
"""Impacchetta gli artefatti che il brain serve agli installer di deploy.

Perche' esiste
--------------
`GET /deploy/bootstrap-artifacts/<agent>-latest.zip` serve un file che deve
esistere in `ARTIFACT_DIR`: senza, l'one-liner di enrollment ("deploy da
remoto") scarica un 404, la registrazione del servizio non parte e sul target
non compare nessun host. Nessuno script lo produceva — si componeva lo zip a
mano, quindi il percorso remoto non era riproducibile.

Questo script mette nell'artefatto **le stesse cose che copia l'installer
locale** (`aegis-guard/install/windows/install.ps1`), cosi' un agente
installato da remoto e uno installato a mano si comportano allo stesso modo:

  aegis-guard-<v>.zip    aegis-guard.jar, jre/ (se presente), aegis-etw.exe
                         (telemetria kernel), bin/yara64.exe (scansione FIM/YARA)
  nodetrace-<v>.zip      intero bundle PyInstaller (dist/nodetrace-agent/)
  aegis-guard-<v>.tar.gz solo runtime: un JRE Windows dentro un tar per Linux
                         non servirebbe a nulla (li' Java 21+ deve esserci host)

Un artefatto incompleto e' peggio di uno assente: se manca il runtime lo script
fallisce; se manca un pezzo opzionale lo DICHIARA (nessun silenzio).

Uso:
  python scripts/pack-artifacts.py [--out DIR] [--version v4.0.0]
"""
import argparse
import os
import sys
import tarfile
import zipfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

GUARD_JAR = os.path.join(REPO, "aegis-guard", "target", "aegis-guard.jar")
# build.bat crea il runtime con jlink in `jre`; se la cartella era bloccata
# (agente in esecuzione) il jlink recente finisce in `jre-new`.
GUARD_JRE_DIRS = [os.path.join(REPO, "aegis-guard", "jre"),
                  os.path.join(REPO, "aegis-guard", "jre-new")]
ETW_EXE = os.path.join(REPO, "aegis-ebpf", "aegis-etw.exe")
YARA_EXE = os.path.join(REPO, "aegis-guard", "bin", "yara64.exe")
NT_DIST = os.path.join(REPO, "NodeTrace", "agents", "python", "dist", "nodetrace-agent")
NT_EXE_NAME = "nodetrace-agent.exe"

DEFAULT_OUT = os.path.join(REPO, "aegis-brain", "artifacts")


def _add_tree(zf, src_dir, prefix):
    """Aggiunge una cartella allo zip mantenendo i path relativi."""
    added = 0
    for root, _dirs, files in os.walk(src_dir):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, src_dir)
            zf.write(full, os.path.join(prefix, rel).replace("\\", "/"))
            added += 1
    return added


def _add_file(zf, path, arcname):
    if os.path.isfile(path):
        zf.write(path, arcname)
        return True
    return False


def _tar_add(tar, path, arcname):
    if os.path.isfile(path):
        tar.add(path, arcname=arcname)
        return True
    return False


def _first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def pack_guard(out_dir, version):
    """ZIP Windows + TAR.GZ Linux di Aegis-Guard. Ritorna (file, note)."""
    if not os.path.isfile(GUARD_JAR):
        raise SystemExit(f"[X] runtime mancante: {GUARD_JAR}\n"
                         "    costrurilo con `build.bat` (o `mvn -f aegis-guard/pom.xml package`).")
    jre_dir = _first_existing(GUARD_JRE_DIRS)
    notes = []
    if not jre_dir:
        notes.append("nessun JRE incluso: il target deve avere Java 21+ "
                     "(`build.bat` crea aegis-guard/jre con jlink)")

    zpath = os.path.join(out_dir, f"aegis-guard-{version}.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        _add_file(zf, GUARD_JAR, "aegis-guard.jar")
        if jre_dir:
            n = _add_tree(zf, jre_dir, "jre")
            notes.append(f"jre/: {n} file")
        if _add_file(zf, ETW_EXE, "aegis-etw.exe"):
            notes.append("aegis-etw.exe incluso (telemetria kernel)")
        else:
            notes.append("collector ETW assente: Guard gira in polling e lo dichiara")
        if _add_file(zf, YARA_EXE, "bin/yara64.exe"):
            notes.append("bin/yara64.exe incluso")
        else:
            notes.append("yara64.exe assente: la scansione YARA locale resta spenta")

    tpath = os.path.join(out_dir, f"aegis-guard-{version}.tar.gz")
    with tarfile.open(tpath, "w:gz") as tar:
        _tar_add(tar, GUARD_JAR, "aegis-guard.jar")
    return [zpath, tpath], notes


def pack_nodetrace(out_dir, version):
    """ZIP/TAR.GZ di NodeTrace dal bundle PyInstaller."""
    if not os.path.isdir(NT_DIST):
        raise SystemExit(f"[X] bundle mancante: {NT_DIST}\n"
                         "    costruiscilo con `cd NodeTrace/agents/python && build.bat`.")
    if not os.path.isfile(os.path.join(NT_DIST, NT_EXE_NAME)):
        raise SystemExit(f"[X] {NT_EXE_NAME} non trovato in {NT_DIST}")

    zpath = os.path.join(out_dir, f"nodetrace-{version}.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        files = _add_tree(zf, NT_DIST, ".")

    tpath = os.path.join(out_dir, f"nodetrace-{version}.tar.gz")
    with tarfile.open(tpath, "w:gz") as tar:
        for root, _dirs, names in os.walk(NT_DIST):
            for name in names:
                full = os.path.join(root, name)
                tar.add(full, arcname=os.path.relpath(full, NT_DIST))
    return [zpath, tpath], [f"bundle completo: {files} file"]


def publish(out_dir, produced, version):
    """Alias `-latest`: e' il nome che l'installer chiede, sempre l'ultimo build."""
    published = []
    for path in produced:
        name = os.path.basename(path)
        latest = name.replace(f"-{version}", "-latest")
        latest_path = os.path.join(out_dir, latest)
        with open(path, "rb") as src, open(latest_path, "wb") as dst:
            dst.write(src.read())
        published.append(latest_path)
    return published


def main():
    ap = argparse.ArgumentParser(description="Pack agent deploy artifacts")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help=f"cartella servita dal brain (default: {DEFAULT_OUT})")
    ap.add_argument("--version", default="v4.0.0", help="versione nell'artefatto (default: v4.0.0)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    produced, all_notes = [], []
    for label, fn in (("aegis-guard", pack_guard), ("nodetrace", pack_nodetrace)):
        files, notes = fn(args.out, args.version)
        produced.extend(files)
        all_notes.append((label, notes))

    latest = publish(args.out, produced, args.version)

    print(f"Artefatti in {args.out}:")
    for f in produced:
        print(f"  {os.path.basename(f)}  ({os.path.getsize(f) // 1024} KB)")
    for f in latest:
        print(f"  {os.path.basename(f)}  ({os.path.getsize(f) // 1024} KB)  <- nome atteso dall'installer")
    for label, notes in all_notes:
        print(f"[{label}]")
        for n in notes:
            print(f"  - {n}")
    print("\nTarget: `irm <base>/api/v1/deploy/install.ps1 -Headers @{'X-Enroll-Token'='<token>'} | iex`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
