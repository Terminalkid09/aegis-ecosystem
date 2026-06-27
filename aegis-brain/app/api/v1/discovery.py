import asyncio
import ipaddress
import os
import platform
import re
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import Agent, DiscoveredHost, IPReputation, Note


router = APIRouter(tags=["Aegis Discovery"])

DEFAULT_SCAN_PORTS = [22, 80, 135, 139, 443, 445, 3389, 8000, 8080]
# OUI prefixes for MAC vendor lookup
_OUI_CACHE: Dict[str, str] = {}
_OUI_URL = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"


async def _load_oui_cache():
    if _OUI_CACHE:
        return
    try:
        import urllib.request
        with urllib.request.urlopen(_OUI_URL, timeout=5) as f:
            for line in f.read().decode("utf-8", errors="ignore").splitlines():
                if line.strip() and not line.startswith("#"):
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        prefix = parts[0].strip().replace(":", "").upper()[:6]
                        vendor = parts[1].strip()
                        _OUI_CACHE[prefix] = vendor
    except Exception:
        import json
        local_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "oui_cache.json")
        if os.path.exists(local_path):
            try:
                with open(local_path) as f:
                    _OUI_CACHE.update(json.load(f))
            except Exception:
                pass


def _mac_to_vendor(mac: str) -> Optional[str]:
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _OUI_CACHE.get(prefix, "Unknown")


def _guess_os_from_ports(open_ports: List[int]) -> str:
    if 3389 in open_ports or 445 in open_ports or 135 in open_ports:
        return "windows"
    if 22 in open_ports:
        return "linux"
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        return "network-service"
    if 8000 in open_ports:
        return "aegis-agent"
    return "unknown"


async def _arp_scan_local(cidr: str) -> List[Dict[str, str]]:
    results = []
    is_windows = platform.system() == "Windows"
    try:
        if is_windows:
            cmd = f"arp -a"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip = parts[0]
                    mac = parts[1].replace("-", ":") if "-" in parts[1] else parts[1]
                    if mac.count(":") == 5 and mac != "00:00:00:00:00:00":
                        results.append({"ip": ip, "mac": mac.upper()})
        else:
            cmd = f"arp -n"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip = parts[0]
                    mac = parts[2] if len(parts[2].split(":")) == 6 else ""
                    if mac and mac != "00:00:00:00:00:00":
                        results.append({"ip": ip, "mac": mac.upper()})
    except Exception:
        pass
    return results


async def _ping_host(ip: str) -> bool:
    is_windows = platform.system() == "Windows"
    param = "-n 1 -w 500" if is_windows else "-c 1 -W 1"
    try:
        proc = await asyncio.create_subprocess_shell(
            f"ping {param} {ip}", stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False


def _host_out(host: DiscoveredHost) -> Dict[str, Any]:
    def agent_status() -> str:
        if host.guard_status == "active" or host.nodetrace_status == "active":
            parts = []
            if host.guard_status == "active":
                parts.append("Guard")
            if host.nodetrace_status == "active":
                parts.append("NodeTrace")
            return f"active ({' + '.join(parts)})"
        if host.guard_status == "deployed" or host.nodetrace_status == "deployed":
            return "deployed"
        return "not_deployed"
    return {
        "id": host.id,
        "ip_address": host.ip_address,
        "hostname": host.hostname,
        "mac_address": host.mac_address,
        "vendor": host.vendor,
        "os_guess": host.os_guess,
        "os_confidence": host.os_confidence,
        "status": host.status,
        "open_ports": host.open_ports or [],
        "agent_status": agent_status(),
        "guard_status": host.guard_status,
        "nodetrace_status": host.nodetrace_status,
        "source": host.source,
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
        "notes": host.notes,
    }


def _reputation_out(rec: IPReputation) -> Dict[str, Any]:
    return {
        "id": rec.id,
        "ip_address": rec.ip_address,
        "label": rec.label,
        "confidence": rec.confidence,
        "source": rec.source,
        "details": rec.details,
        "updated_at": rec.updated_at,
    }


class DiscoveryScanRequest(BaseModel):
    cidr: str = Field(..., examples=["192.168.1.0/24"])
    ports: List[int] = Field(default_factory=lambda: DEFAULT_SCAN_PORTS)
    timeout_ms: int = Field(default=250, ge=50, le=2000)
    include_unreachable: bool = False
    fast_scan: bool = Field(default=True, description="Use ARP + ICMP sweep first to find live hosts")


class ReputationUpsert(BaseModel):
    ip_address: str
    label: str = Field(..., pattern="^(known|suspicious|malicious|unknown)$")
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = "manual"
    details: Optional[Dict[str, Any]] = None


class DeploymentPlanRequest(BaseModel):
    ip_address: str
    os_type: str = Field(default="linux", pattern="^(linux|windows)$")
    agent_type: str = Field(default="nodetrace", pattern="^(nodetrace|aegis-guard)$")
    method: str = Field(default="manual", pattern="^(manual|ssh|winrm)$")


class AutoDeployRequest(BaseModel):
    ip_address: str
    agent_type: str = Field(default="nodetrace", pattern="^(nodetrace|aegis-guard)$")
    username: Optional[str] = None
    password: Optional[str] = None


async def _check_port(ip: str, port: int, timeout: float) -> Optional[int]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


def _safe_network(cidr: str):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {exc}") from exc
    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="Discovery scan is limited to 256 addresses")
    if not (network.is_private or network.is_loopback):
        raise HTTPException(status_code=400, detail="Discovery scan is limited to private or loopback networks")
    return network


async def _sync_agent_status(db: AsyncSession, ip: str, host: DiscoveredHost):
    result = await db.execute(select(Agent).where(Agent.ip_address == ip))
    agents = result.scalars().all()
    for agent in agents:
        threshold = datetime.now(timezone.utc).timestamp() - 600
        is_active = agent.last_seen.timestamp() > threshold if agent.last_seen else False
        is_deployed = agent.last_seen is not None
        if agent.agent_type == "aegis-guard":
            host.guard_status = "active" if is_active else ("deployed" if is_deployed else "not_deployed")
        elif agent.agent_type in ("nodetrace", "NodeTrace"):
            host.nodetrace_status = "active" if is_active else ("deployed" if is_deployed else "not_deployed")


async def _upsert_host(db: AsyncSession, ip: str, open_ports: List[int], source: str = "scan", mac: Optional[str] = None) -> DiscoveredHost:
    result = await db.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == ip))
    host = result.scalars().first()
    status_value = "reachable" if open_ports else "unknown"
    hostname = None
    try:
        hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
        hostname = hostname[0]
    except Exception:
        pass
    vendor = _mac_to_vendor(mac) if mac else None
    if host:
        host.hostname = hostname or host.hostname
        if mac:
            host.mac_address = mac
            host.vendor = vendor
        host.os_guess = _guess_os_from_ports(open_ports) if open_ports else host.os_guess
        host.status = status_value
        host.open_ports = open_ports
        host.source = source
        host.last_seen = datetime.now(timezone.utc)
    else:
        os_guess = _guess_os_from_ports(open_ports) if open_ports else "unknown"
        host = DiscoveredHost(
            ip_address=ip,
            hostname=hostname,
            mac_address=mac,
            vendor=vendor,
            os_guess=os_guess,
            os_confidence=90 if open_ports else 10,
            status=status_value,
            open_ports=open_ports,
            source=source,
        )
        db.add(host)
    await _sync_agent_status(db, ip, host)
    return host


@router.post("/scan")
async def scan_network(payload: DiscoveryScanRequest, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    network = _safe_network(payload.cidr)
    ports = [p for p in payload.ports if 1 <= p <= 65535][:32]
    timeout = payload.timeout_ms / 1000
    discovered = []

    await _load_oui_cache()

    arp_hosts = await _arp_scan_local(payload.cidr) if payload.fast_scan else []
    arp_ips = {h["ip"] for h in arp_hosts}

    ping_tasks = {}
    for addr in network.hosts() if network.num_addresses > 2 else network:
        ip = str(addr)
        if ip in arp_ips:
            continue
        ping_tasks[ip] = asyncio.ensure_future(_ping_host(ip))

    live_ips = set(arp_ips)
    for ip, task in ping_tasks.items():
        if await task:
            live_ips.add(ip)

    for ip in sorted(live_ips):
        checks = await asyncio.gather(*[_check_port(ip, port, timeout) for port in ports])
        open_ports = sorted([port for port in checks if port is not None])
        mac = next((h["mac"] for h in arp_hosts if h["ip"] == ip), None)
        host = await _upsert_host(db, ip, open_ports, mac=mac)
        discovered.append(host)

    if payload.include_unreachable:
        for addr in network.hosts() if network.num_addresses > 2 else network:
            ip = str(addr)
            if ip not in live_ips:
                host = await _upsert_host(db, ip, [], source="scan")
                discovered.append(host)

    await db.commit()
    return {
        "cidr": str(network),
        "scanned_hosts": network.num_addresses,
        "live_hosts": len(live_ips),
        "discovered": [_host_out(h) for h in discovered],
    }


@router.get("/hosts")
async def list_hosts(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(DiscoveredHost).order_by(DiscoveredHost.last_seen.desc()).limit(250))
    return {"items": [_host_out(item) for item in result.scalars().all()]}


@router.post("/reputation")
async def upsert_reputation(payload: ReputationUpsert, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    try:
        ipaddress.ip_address(payload.ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc
    result = await db.execute(select(IPReputation).where(IPReputation.ip_address == payload.ip_address))
    rec = result.scalars().first()
    if rec:
        rec.label = payload.label
        rec.confidence = payload.confidence
        rec.source = payload.source
        rec.details = payload.details
        rec.updated_at = datetime.now(timezone.utc)
    else:
        rec = IPReputation(**payload.model_dump())
        db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return _reputation_out(rec)


@router.get("/reputation")
async def list_reputation(db: AsyncSession = Depends(get_db), user=Depends(get_current_user), label: Optional[str] = Query(None)):
    stmt = select(IPReputation).order_by(IPReputation.updated_at.desc())
    if label:
        stmt = stmt.where(IPReputation.label == label)
    result = await db.execute(stmt.limit(250))
    return {"items": [_reputation_out(item) for item in result.scalars().all()]}


@router.post("/demo/start")
async def start_demo(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    demo_hosts = [
        {"ip": "10.10.10.21", "hostname": "demo-win-endpoint", "os": "windows", "type": "aegis-guard", "ports": [135, 445, 3389]},
        {"ip": "10.10.10.42", "hostname": "demo-linux-sensor", "os": "linux", "type": "nodetrace", "ports": [22, 8000]},
        {"ip": "10.10.10.55", "hostname": "demo-android-device", "os": "android", "type": "nodetrace", "ports": [], "mac": "A4:C3:F0:12:34:56"},
    ]
    agents = []
    for item in demo_hosts:
        agent_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"aegis-demo:{item['hostname']}")
        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalars().first()
        if not agent:
            agent = Agent(
                agent_id=agent_id,
                hostname=item["hostname"],
                ip_address=item["ip"],
                os_type=item.get("os", "unknown"),
                agent_type=item["type"],
                is_demo=True,
                last_seen=now,
            )
            db.add(agent)
        else:
            agent.last_seen = now
            agent.is_demo = True
        host = await _upsert_host(db, item["ip"], item.get("ports", []), source="demo", mac=item.get("mac"))
        host.hostname = item["hostname"]
        host.vendor = _mac_to_vendor(item.get("mac", "")) if item.get("mac") else None
        if item.get("type") == "aegis-guard":
            host.guard_status = "active"
        else:
            host.nodetrace_status = "active"
        agents.append(agent)

    await db.commit()
    return {"status": "demo_started", "agents": [{"agent_id": str(a.agent_id), "hostname": a.hostname} for a in agents]}


@router.post("/demo/heartbeat")
async def demo_heartbeat(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Agent).where(Agent.is_demo == True))
    agents = result.scalars().all()
    for agent in agents:
        agent.last_seen = now
    await db.commit()
    return {"status": "heartbeat_refreshed", "count": len(agents)}


@router.post("/deployment/plan")
async def deployment_plan(payload: DeploymentPlanRequest, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    try:
        ipaddress.ip_address(payload.ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc

    creds = {"username": None, "password": None}
    result = await db.execute(select(Note).where(Note.tags != None))
    for note in result.scalars().all():
        if isinstance(note.tags, dict):
            tags = note.tags.get("tags", []) if isinstance(note.tags, dict) else []
            tags = note.tags if isinstance(note.tags, list) else tags
            if isinstance(tags, str):
                tokens = [t.strip().lower() for t in tags.split(",")]
            elif isinstance(tags, list):
                tokens = [str(t).strip().lower() for t in tags]
            else:
                tokens = []
            if "#deploy-creds" in tokens or "deploy-creds" in tokens:
                content_lower = note.content.lower()
                if payload.ip_address in note.content:
                    for line in note.content.splitlines():
                        if "password:" in line.lower() or "pass:" in line.lower():
                            creds["password"] = line.split(":", 1)[1].strip()
                        if "user:" in line.lower() or "username:" in line.lower():
                            creds["username"] = line.split(":", 1)[1].strip()

    if payload.method == "winrm" and creds["username"] and creds["password"]:
        deploy_command = (
            f"powershell -Command \"$secpass=ConvertTo-SecureString '{creds['password']}' -AsPlainText -Force; "
            f"$cred=New-Object System.Management.Automation.PSCredential('{creds['username']}', $secpass); "
            f"Invoke-Command -ComputerName {payload.ip_address} -Credential $cred -ScriptBlock {{ "
        )
        if payload.agent_type == "aegis-guard":
            deploy_command += (
                "Invoke-WebRequest -Uri 'http://aegis-brain:8000/api/v1/enroll/download/aegis-guard.exe' -OutFile 'C:\\AegisGuard\\aegis-guard.exe'; "
                "Start-Process -FilePath 'C:\\AegisGuard\\aegis-guard.exe' -NoNewWindow -RedirectStandardOutput 'C:\\AegisGuard\\install.log' }}"
            )
        else:
            deploy_command += (
                "Invoke-WebRequest -Uri 'http://aegis-brain:8000/api/v1/enroll/download/nodetrace.py' -OutFile 'C:\\NodeTrace\\agent.py'; "
                "Start-Process -FilePath 'python' -ArgumentList 'C:\\NodeTrace\\agent.py' -NoNewWindow }}"
            )
        payload_method = "winrm"
    elif payload.method == "ssh" and creds["username"] and creds["password"]:
        agent_script = "python3 NodeTrace/agents/python/agent.py" if payload.agent_type == "nodetrace" else "java -jar aegis-guard.jar"
        deploy_command = f"sshpass -p '{creds['password']}' ssh -o StrictHostKeyChecking=no {creds['username']}@{payload.ip_address} '{agent_script} &'"
        payload_method = "ssh"
    else:
        deploy_command = None
        payload_method = "manual"

    if payload.agent_type == "nodetrace":
        local_command = "cd NodeTrace\\agents\\python && python agent.py"
        remote_command = f"python NodeTrace/agents/python/agent.py  # run on {payload.ip_address}"
    else:
        local_command = "cd aegis-guard && java -jar target\\aegis-guard.jar"
        remote_command = f"java -jar aegis-guard.jar  # run on {payload.ip_address}"

    return {
        "status": "planned",
        "method": payload_method,
        "ip_address": payload.ip_address,
        "agent_type": payload.agent_type,
        "has_credentials": creds["username"] is not None,
        "local_command": local_command,
        "remote_command": remote_command,
        "deploy_command": deploy_command,
        "note": "For WinRM/SSH auto-deploy, save a note in VaultX with tag #deploy-creds containing ip, username, password.",
    }


@router.post("/deploy")
async def auto_deploy(payload: AutoDeployRequest, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    creds = {"username": payload.username, "password": payload.password}
    if not creds["username"] or not creds["password"]:
        result = await db.execute(select(Note).where(Note.tags != None))
        for note in result.scalars().all():
            tags = []
            if isinstance(note.tags, dict) and "tags" in note.tags:
                tags = note.tags["tags"]
            if isinstance(note.tags, list):
                tags = note.tags
            if isinstance(tags, str):
                tokens = [t.strip().lower() for t in tags.split(",")]
            elif isinstance(tags, list):
                tokens = [str(t).strip().lower() for t in tags]
            else:
                tokens = []
            if "#deploy-creds" in tokens or "deploy-creds" in tokens:
                if payload.ip_address in note.content:
                    for line in note.content.splitlines():
                        if "password:" in line.lower() or "pass:" in line.lower():
                            creds["password"] = line.split(":", 1)[1].strip()
                        if "user:" in line.lower() or "username:" in line.lower():
                            creds["username"] = line.split(":", 1)[1].strip()

    if not creds["username"] or not creds["password"]:
        raise HTTPException(status_code=400, detail="No credentials found. Save a VaultX note with #deploy-creds tag.")

    os_type = "windows" if 445 in [p for p in []] else "linux"
    try:
        result = await db.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == payload.ip_address))
        host = result.scalars().first()
        if host and host.open_ports:
            if 445 in host.open_ports or 3389 in host.open_ports or 135 in host.open_ports:
                os_type = "windows"
    except Exception:
        pass

    if os_type == "windows":
        if not creds["username"] or not creds["password"]:
            raise HTTPException(status_code=400, detail="Windows deploy requires username and password from Vault.")
        return {
            "status": "deploy_initiated",
            "ip_address": payload.ip_address,
            "agent_type": payload.agent_type,
            "method": "winrm",
            "command": (
                f"powershell -Command \"$secpass=ConvertTo-SecureString '{creds['password']}' -AsPlainText -Force; "
                f"$cred=New-Object System.Management.Automation.PSCredential('{creds['username']}', $secpass); "
                f"Invoke-Command -ComputerName {payload.ip_address} -Credential $cred -ScriptBlock {{ "
                f"Start-Process -FilePath 'powershell' -ArgumentList '-Command \"& {{ "
                f"$url=\"http://aegis-brain:8000/api/v1/enroll/download/{payload.agent_type}.py\"; "
                f"$out=\"C:\\Aegis\\{payload.agent_type}.py\"; "
                f"New-Item -ItemType Directory -Force -Path \"C:\\Aegis\"; "
                f"Invoke-WebRequest -Uri $url -OutFile $out; python $out"
                f" }}\" -NoNewWindow -WindowStyle Hidden'"
                f"}} -ErrorAction Stop\""
            ),
            "note": "Deploy running in background on target. Check agent list in 30s.",
        }
    else:
        return {
            "status": "deploy_initiated",
            "ip_address": payload.ip_address,
            "agent_type": payload.agent_type,
            "method": "ssh",
            "command": f"sshpass -p '{creds['password']}' ssh -o StrictHostKeyChecking=no {creds['username']}@{payload.ip_address} 'curl -sL http://aegis-brain:8000/api/v1/enroll/download/nodetrace.py | python3 &'",
            "note": "Deploy running in background on target. Check agent list in 30s.",
        }


@router.post("/sync-agent-status")
async def sync_agent_status(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    hosts_result = await db.execute(select(DiscoveredHost))
    hosts = hosts_result.scalars().all()
    threshold = (datetime.now(timezone.utc).timestamp() - 600)

    for host in hosts:
        result = await db.execute(select(Agent).where(Agent.ip_address == host.ip_address))
        agents = result.scalars().all()
        for agent in agents:
            is_active = agent.last_seen.timestamp() > threshold if agent.last_seen else False
            is_deployed = agent.last_seen is not None
            if agent.agent_type == "aegis-guard":
                host.guard_status = "active" if is_active else ("deployed" if is_deployed else "not_deployed")
            elif agent.agent_type in ("nodetrace", "NodeTrace"):
                host.nodetrace_status = "active" if is_active else ("deployed" if is_deployed else "not_deployed")

    await db.commit()
    return {"status": "synced", "count": len(hosts)}
