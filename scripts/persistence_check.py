#!/usr/bin/env python3
"""Audit the checked-in reboot/crash contracts.

Static mode is safe in CI and does not touch the host. It verifies that the
MSI, systemd units, one-liners, OpenWrt procd service and Compose files still
contain the persistence primitives the release claims. Live mode is explicit:
it never elevates, never invokes UAC and never installs a service.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(relative: str) -> str:
    try:
        return (ROOT / relative).read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read {relative}: {exc}") from exc


def static_failures() -> list[str]:
    failures: list[str] = []

    msi = _text("aegis-agent/packaging/windows/aegis-agent.wxs")
    if 'Scope="perMachine"' not in msi:
        failures.append("MSI must install per-machine, not per-user")
    if 'Start="auto"' not in msi:
        failures.append("MSI service is not configured for automatic startup")
    if msi.count('FailureActionType="restart"') < 3:
        failures.append("MSI service recovery does not contain three restarts")
    if 'Remove="uninstall"' not in msi:
        failures.append("MSI service is not removed on uninstall")

    unit = _text("aegis-agent/packaging/linux/lib/systemd/system/aegis-agent.service")
    for needle in ("Restart=always", "RestartSec=5s", "StartLimitIntervalSec=0",
                   "WantedBy=multi-user.target"):
        if needle not in unit:
            failures.append(f"packaged systemd unit is missing {needle}")

    deploy = _text("aegis-brain/app/api/v1/deploy.py")
    for needle in ("New-Service", "-StartupType Automatic", "sc.exe failure",
                   "sc.exe qfailure", "WaitForStatus", "StartType"):
        if needle not in deploy:
            failures.append(f"Windows one-liner is missing {needle}")
    for needle in ("systemctl daemon-reload", "systemctl enable --now",
                   "systemctl is-enabled --quiet", "systemctl is-active --quiet",
                   "StartLimitIntervalSec=0", "Restart=always"):
        if needle not in deploy:
            failures.append(f"Linux one-liner is missing {needle}")

    opkg = _text("scripts/build-opkg.sh")
    if "procd_set_param respawn" not in opkg:
        failures.append("OpenWrt service has no procd respawn")
    if "/etc/init.d/aegis-agent enable" not in opkg:
        failures.append("OpenWrt postinst does not enable the service")

    postinst = _text("aegis-agent/packaging/linux/DEBIAN/postinst")
    if "[ -d /run/systemd/system ]" not in postinst:
        failures.append("deb postinst cannot distinguish a booted host from a chroot")
    if "systemctl is-enabled --quiet aegis-agent.service" not in postinst:
        failures.append("deb postinst does not verify boot enablement")

    for pkg, unit_name in (("aegis", "aegis"),
                           ("kraken", "kraken")):
        unit = _text(f"packaging/server/{pkg}/{unit_name}.service")
        for needle in ("Wants=docker.service", "After=docker.service",
                       "User=root", "ExecStartPre=", "ExecStart=", "ExecStop=",
                       "WantedBy=multi-user.target"):
            if needle not in unit:
                failures.append(f"{pkg} unit is missing {needle}")
        server_postinst = _text(f"packaging/server/{pkg}/postinst")
        if "systemctl is-enabled --quiet" not in server_postinst:
            failures.append(f"{pkg} postinst does not verify boot enablement")
        if "AEGIS_PACKAGE_SKIP_START" not in server_postinst:
            failures.append(f"{pkg} postinst cannot be tested without starting Docker")
        if "images.ok" not in server_postinst:
            failures.append(f"{pkg} postinst does not invalidate the image marker")

    compose = "\n".join(
        p.read_text(encoding="utf-8") for p in ROOT.glob("docker-compose*.yml")
    )
    if compose.count("restart: unless-stopped") < 2:
        failures.append("Compose files do not contain long-running restart policies")

    autostart = _text("scripts/install-autostart.ps1")
    if "CurrentVersion\\Run" not in autostart:
        failures.append("Docker Desktop autostart helper is missing the Run key")

    return failures


def _run(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=False, text=True,
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "timeout")


def live_linux() -> list[str]:
    failures: list[str] = []
    if platform.system() != "Linux":
        return ["live Linux check requires a Linux host"]
    if not shutil.which("systemctl"):
        return ["systemctl not found"]
    enabled = _run(["systemctl", "is-enabled", "--quiet", "aegis-agent"])
    if enabled.returncode != 0:
        failures.append("aegis-agent is not enabled at boot")
    restart = _run(["systemctl", "show", "-p", "Restart", "--value", "aegis-agent"])
    if restart.stdout.strip() != "always":
        failures.append(f"aegis-agent Restart={restart.stdout.strip()!r}, expected always")
    active = _run(["systemctl", "is-active", "--quiet", "aegis-agent"])
    if active.returncode != 0:
        failures.append("aegis-agent is not active")
    return failures


def live_windows() -> list[str]:
    if os.name != "nt":
        return ["live Windows check requires Windows"]
    script = (
        "$s=Get-Service AegisAgent -ErrorAction SilentlyContinue; "
        "if(-not $s){'NOT_INSTALLED'; exit 0}; "
        "$s | Select-Object Name,Status,StartType | ConvertTo-Json -Compress; "
        "sc.exe qfailure AegisAgent | Out-String"
    )
    result = _run(["powershell", "-NoProfile", "-Command", script])
    if "NOT_INSTALLED" in result.stdout:
        return ["AegisAgent is not installed as a Windows service"]
    if result.returncode != 0:
        return [f"PowerShell service check failed: {result.stderr.strip()}"]
    if '"StartType":2' not in result.stdout.replace(" ", ""):
        failures = ["AegisAgent start type is not Automatic"]
    else:
        failures = []
    if "RESTART" not in result.stdout.upper() and "RIAVVIA" not in result.stdout.upper():
        failures.append("AegisAgent recovery actions are not configured")
    return failures


def live_containers() -> list[str]:
    failures: list[str] = []
    for name in ("aegis-brain", "aegis-kraken", "aegis-kraken-sensors", "aegis-kraken-broker"):
        result = _run(["docker", "inspect", "-f",
                       "{{.HostConfig.RestartPolicy.Name}}", name])
        if result.returncode != 0:
            failures.append(f"container {name} is missing")
            continue
        policy = result.stdout.strip()
        if policy != "unless-stopped":
            failures.append(f"container {name} restart policy is {policy!r}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-linux", action="store_true")
    parser.add_argument("--live-windows", action="store_true")
    parser.add_argument("--containers", action="store_true")
    args = parser.parse_args(argv)

    failures = static_failures()
    if args.live_linux:
        failures += live_linux()
    if args.live_windows:
        failures += live_windows()
    if args.containers:
        failures += live_containers()
    print(json.dumps({"passed": not failures, "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
