import asyncio
import ipaddress
import os
import platform
import re
import shlex
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_deps import get_current_agent
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
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    is_windows = platform.system() == "Windows"
    args = ["ping", "-n", "1", "-w", "500", ip] if is_windows else ["ping", "-c", "1", "-W", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        await proc.communicate()
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


def _sanitize_cred(s: str) -> str:
    """Strip shell-dangerous characters from a credential string."""
    return re.sub(r"[^\w@.\-\\/]", "", s)


def _validate_ip_or_raise(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}") from exc


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

    # Fallback: known agents from DB
    known_ips = set()
    try:
        agent_result = await db.execute(select(Agent.ip_address).where(Agent.ip_address != None))
        known_ips = {row[0] for row in agent_result.all() if row[0]}
        known_hosts_result = await db.execute(select(DiscoveredHost.ip_address))
        known_ips |= {row[0] for row in known_hosts_result.all() if row[0]}
    except Exception:
        pass

    all_addrs = list(network.hosts()) if network.num_addresses > 2 else list(network)
    ping_tasks = {}
    for addr in all_addrs:
        ip = str(addr)
        if ip in arp_ips or ip in known_ips:
            continue
        ping_tasks[ip] = asyncio.ensure_future(_ping_host(ip))

    known_in_network = known_ips & {str(addr) for addr in all_addrs}
    live_ips = set(arp_ips) | known_in_network
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
        all_addrs2 = list(network.hosts()) if network.num_addresses > 2 else list(network)
        for addr in all_addrs2:
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

    _validate_ip_or_raise(payload.ip_address)
    safe_user = _sanitize_cred(creds["username"] or "")
    safe_pass = _sanitize_cred(creds["password"] or "")

    if payload.method == "winrm" and safe_user and safe_pass:
        quoted_pass = shlex.quote(safe_pass)
        quoted_user = shlex.quote(safe_user)
        if payload.agent_type == "aegis-guard":
            deploy_command = (
                f"powershell -Command \"$secpass=ConvertTo-SecureString {quoted_pass} -AsPlainText -Force; "
                f"$cred=New-Object System.Management.Automation.PSCredential({quoted_user}, $secpass); "
                f"$s=New-PSSession -ComputerName {payload.ip_address} -Credential $cred; "
                f"Invoke-Command -Session $s -ScriptBlock {{ New-Item -ItemType Directory -Force -Path 'C:\\AegisGuard' }}; "
                f"Copy-Item -ToSession $s -Path 'aegis-guard\\target\\aegis-guard.jar' -Destination 'C:\\AegisGuard\\aegis-guard.jar'; "
                f"Invoke-Command -Session $s -ScriptBlock {{ "
                f"Start-Process -FilePath 'java' -ArgumentList '-jar','C:\\AegisGuard\\aegis-guard.jar' -NoNewWindow "
                f"}}; Remove-PSSession $s\""
            )
        else:
            deploy_command = (
                f"powershell -Command \"$secpass=ConvertTo-SecureString {quoted_pass} -AsPlainText -Force; "
                f"$cred=New-Object System.Management.Automation.PSCredential({quoted_user}, $secpass); "
                f"$s=New-PSSession -ComputerName {payload.ip_address} -Credential $cred; "
                f"Invoke-Command -Session $s -ScriptBlock {{ New-Item -ItemType Directory -Force -Path 'C:\\NodeTrace' }}; "
                f"Copy-Item -ToSession $s -Path 'NodeTrace\\agents\\python\\dist\\nodetrace-agent\\*' -Destination 'C:\\NodeTrace\\' -Recurse -Force; "
                f"Invoke-Command -Session $s -ScriptBlock {{ "
                f"Start-Process -FilePath 'C:\\NodeTrace\\nodetrace-agent.exe' -NoNewWindow "
                f"}}; Remove-PSSession $s\""
            )
        payload_method = "winrm"
    elif payload.method == "ssh" and safe_user and safe_pass:
        if payload.agent_type == "aegis-guard":
            deploy_command = (
                f"sshpass -p {shlex.quote(safe_pass)} scp -o StrictHostKeyChecking=no "
                f"aegis-guard/target/aegis-guard.jar {shlex.quote(safe_user)}@{payload.ip_address}:/tmp/aegis-guard.jar && "
                f"sshpass -p {shlex.quote(safe_pass)} ssh -o StrictHostKeyChecking=no "
                f"{shlex.quote(safe_user)}@{payload.ip_address} "
                f"'nohup java -jar /tmp/aegis-guard.jar > /tmp/aegis-guard.log 2>&1 &'"
            )
        else:
            deploy_command = (
                f"sshpass -p {shlex.quote(safe_pass)} scp -r -o StrictHostKeyChecking=no "
                f"NodeTrace/agents/python/dist/nodetrace-agent {shlex.quote(safe_user)}@{payload.ip_address}:/tmp/nodetrace-agent && "
                f"sshpass -p {shlex.quote(safe_pass)} ssh -o StrictHostKeyChecking=no "
                f"{shlex.quote(safe_user)}@{payload.ip_address} "
                f"'chmod +x /tmp/nodetrace-agent/nodetrace-agent && nohup /tmp/nodetrace-agent/nodetrace-agent > /tmp/nodetrace.log 2>&1 &'"
            )
        payload_method = "ssh"
    else:
        deploy_command = None
        payload_method = "manual"

    if payload.agent_type == "nodetrace":
        local_command = "cd NodeTrace\\agents\\python\\dist\\nodetrace-agent && nodetrace-agent.exe"
        remote_command = f"Copy nodetrace-agent folder to {payload.ip_address} and run nodetrace-agent.exe"
    else:
        local_command = "cd aegis-guard && java -jar target\\aegis-guard.jar"
        remote_command = f"Copy aegis-guard.jar to {payload.ip_address} and run: java -jar aegis-guard.jar"

    return {
        "status": "planned",
        "method": payload_method,
        "ip_address": payload.ip_address,
        "agent_type": payload.agent_type,
        "has_credentials": creds["username"] is not None,
        "local_command": local_command,
        "remote_command": remote_command,
        "deploy_command": deploy_command,
        "executables": {
            "nodetrace": "NodeTrace/agents/python/dist/nodetrace-agent/nodetrace-agent.exe",
            "guard_jar": "aegis-guard/target/aegis-guard.jar",
        },
        "note": "For WinRM/SSH auto-deploy, save a note in VaultX with tag #deploy-creds containing ip, username, password.",
    }


@router.post("/deploy")
async def auto_deploy(payload: AutoDeployRequest, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    _validate_ip_or_raise(payload.ip_address)
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

    safe_user = _sanitize_cred(creds["username"] or "")
    safe_pass = _sanitize_cred(creds["password"] or "")
    if not safe_user or not safe_pass:
        raise HTTPException(status_code=400, detail="No credentials found. Save a VaultX note with #deploy-creds tag.")

    os_type = "linux"
    try:
        result = await db.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == payload.ip_address))
        host = result.scalars().first()
        if host and host.open_ports:
            if 445 in host.open_ports or 3389 in host.open_ports or 135 in host.open_ports:
                os_type = "windows"
        if host and host.os_guess and "windows" in host.os_guess.lower():
            os_type = "windows"
    except Exception:
        pass

    quoted_user = shlex.quote(safe_user)
    quoted_pass = shlex.quote(safe_pass)

    if os_type == "windows":
        if payload.agent_type == "aegis-guard":
            command = (
                f"powershell -Command \"$secpass=ConvertTo-SecureString {quoted_pass} -AsPlainText -Force; "
                f"$cred=New-Object System.Management.Automation.PSCredential({quoted_user}, $secpass); "
                f"$s=New-PSSession -ComputerName {payload.ip_address} -Credential $cred; "
                f"Invoke-Command -Session $s -ScriptBlock {{ New-Item -ItemType Directory -Force -Path 'C:\\AegisGuard' }}; "
                f"Copy-Item -ToSession $s -Path 'aegis-guard\\target\\aegis-guard.jar' -Destination 'C:\\AegisGuard\\aegis-guard.jar'; "
                f"Invoke-Command -Session $s -ScriptBlock {{ "
                f"Start-Process -FilePath 'java' -ArgumentList '-jar','C:\\AegisGuard\\aegis-guard.jar' -NoNewWindow "
                f"}}; Remove-PSSession $s\""
            )
        else:
            command = (
                f"powershell -Command \"$secpass=ConvertTo-SecureString {quoted_pass} -AsPlainText -Force; "
                f"$cred=New-Object System.Management.Automation.PSCredential({quoted_user}, $secpass); "
                f"$s=New-PSSession -ComputerName {payload.ip_address} -Credential $cred; "
                f"Invoke-Command -Session $s -ScriptBlock {{ New-Item -ItemType Directory -Force -Path 'C:\\NodeTrace' }}; "
                f"Copy-Item -ToSession $s -Path 'NodeTrace\\agents\\python\\dist\\nodetrace-agent\\*' -Destination 'C:\\NodeTrace\\' -Recurse -Force; "
                f"Invoke-Command -Session $s -ScriptBlock {{ "
                f"Start-Process -FilePath 'C:\\NodeTrace\\nodetrace-agent.exe' -NoNewWindow "
                f"}}; Remove-PSSession $s\""
            )
        return {
            "status": "deploy_initiated",
            "ip_address": payload.ip_address,
            "agent_type": payload.agent_type,
            "method": "winrm",
            "os_detected": os_type,
            "command": command,
            "note": "Deploy copies compiled executable to target via WinRM and starts it. Check agent list in 30s.",
        }
    else:
        if payload.agent_type == "aegis-guard":
            command = (
                f"sshpass -p {quoted_pass} scp -o StrictHostKeyChecking=no "
                f"aegis-guard/target/aegis-guard.jar {quoted_user}@{payload.ip_address}:/tmp/aegis-guard.jar && "
                f"sshpass -p {quoted_pass} ssh -o StrictHostKeyChecking=no "
                f"{quoted_user}@{payload.ip_address} "
                f"'nohup java -jar /tmp/aegis-guard.jar > /tmp/aegis-guard.log 2>&1 &'"
            )
        else:
            command = (
                f"sshpass -p {quoted_pass} scp -r -o StrictHostKeyChecking=no "
                f"NodeTrace/agents/python/dist/nodetrace-agent {quoted_user}@{payload.ip_address}:/tmp/nodetrace-agent && "
                f"sshpass -p {quoted_pass} ssh -o StrictHostKeyChecking=no "
                f"{quoted_user}@{payload.ip_address} "
                f"'chmod +x /tmp/nodetrace-agent/nodetrace-agent && nohup /tmp/nodetrace-agent/nodetrace-agent > /tmp/nodetrace.log 2>&1 &'"
            )
        return {
            "status": "deploy_initiated",
            "ip_address": payload.ip_address,
            "agent_type": payload.agent_type,
            "method": "ssh",
            "os_detected": os_type,
            "command": command,
            "note": "Deploy copies compiled executable to target via SCP and starts it. Check agent list in 30s.",
        }


class ManualHostRequest(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    source: str = "manual"

@router.post("/hosts/manual")
async def add_manual_host(payload: ManualHostRequest, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    try:
        ipaddress.ip_address(payload.ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc
    host = await _upsert_host(db, payload.ip_address, [], source=payload.source, mac=payload.mac_address)
    if payload.hostname:
        host.hostname = payload.hostname
    await db.commit()
    return _host_out(host)

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


# ===== SCAN VIA AGENT =====

class ScanViaAgentRequest(BaseModel):
    cidr: str = Field(default="192.168.1.0/24", examples=["192.168.1.0/24"])
    ports: List[int] = Field(default_factory=lambda: DEFAULT_SCAN_PORTS)
    probe_timeout: float = Field(default=0.1, ge=0.01, le=5.0, description="Seconds to wait for ARP probe per host. Higher = more thorough in large/noisy networks.")

class AgentScanResultItem(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    open_ports: List[int] = []
    os_guess: Optional[str] = None

class AgentScanResultRequest(BaseModel):
    cidr: str
    scan_hosts: List[AgentScanResultItem]

@router.post("/scan-via-agent/{agent_id}")
async def scan_network_via_agent(
    agent_id: str,
    payload: ScanViaAgentRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user)
):
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent_obj = result.scalars().first()
    if not agent_obj:
        raise HTTPException(status_code=404, detail="Agent not found")
    import json
    import redis.asyncio as redis_lib
    from app.core.redis_utils import get_redis_url
    rc = redis_lib.from_url(get_redis_url(), decode_responses=True)
    queue_name = f"aegis:commands:{agent_id}"
    command = {
        "command": "NETWORK_SCAN",
        "cidr": payload.cidr,
        "ports": payload.ports,
        "probe_timeout": payload.probe_timeout,
    }
    await rc.rpush(queue_name, json.dumps(command))
    await rc.aclose()
    return {
        "status": "command_queued",
        "agent_id": agent_id,
        "cidr": payload.cidr,
        "note": "Agent will scan on next heartbeat cycle (usually within 5-10 seconds). Results will appear in hosts list when reported."
    }

@router.post("/agent-scan-result")
async def agent_scan_result(
    payload: AgentScanResultRequest,
    db: AsyncSession = Depends(get_db),
    agent_obj: Agent = Depends(get_current_agent)
):
    await _load_oui_cache()
    discovered = []
    for item in payload.scan_hosts:
        host = await _upsert_host(db, item.ip_address, item.open_ports, source=f"agent-scan:{agent_obj.agent_id}", mac=item.mac_address)
        if item.hostname:
            host.hostname = item.hostname
        if item.os_guess:
            host.os_guess = item.os_guess
            host.os_confidence = 80
        discovered.append(host)
    await db.commit()
    return {
        "status": "ok",
        "agent_id": str(agent_obj.agent_id),
        "cidr": payload.cidr,
        "hosts_found": len(discovered),
        "hosts": [_host_out(h) for h in discovered],
    }
