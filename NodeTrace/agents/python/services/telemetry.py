import psutil
import platform
import time
import shutil
import socket
import os

class TelemetryService:
    start_time = time.time()

    def __init__(self):
        self._public_ip = "unknown"
        self._public_ip_at = 0.0

    def get(self):
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram_total = psutil.virtual_memory().total
        ram_available = psutil.virtual_memory().available
        ram_usage = ((ram_total - ram_available) / ram_total) * 100

        disk = psutil.disk_usage('/')
        disk_free = disk.free // (1024 * 1024)
        disk_total = disk.total // (1024 * 1024)

        network = psutil.net_io_counters()
        network_sent = network.bytes_sent
        network_received = network.bytes_recv

        active_connections = len(psutil.net_connections())

        procs = sorted(
            psutil.process_iter(['name', 'pid', 'ppid', 'exe', 'username', 'cpu_percent', 'memory_percent']),
            key=lambda p: p.info['cpu_percent'] or 0,
            reverse=True,
        )[:25]
        processes = []
        for p in procs:
            try:
                pinfo = p.info
                processes.append({
                    "name": pinfo['name'] or 'unknown',
                    "pid": pinfo['pid'],
                    "parent_pid": pinfo.get('ppid'),
                    "path": pinfo.get('exe'),
                    "user": pinfo.get('username'),
                    "cpu_percent": round(pinfo['cpu_percent'] or 0, 1),
                    "memory_percent": round(pinfo.get('memory_percent') or 0, 1),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Collect detailed network flows (connections)
        network_flows = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    network_flows.append({
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "pid": conn.pid,
                        "status": conn.status
                    })
        except (psutil.AccessDenied, PermissionError):
            pass # Unprivileged agents might not see all connections

        # Collect logged in users
        users = []
        try:
            for u in psutil.users():
                users.append({
                    "name": u.name,
                    "terminal": u.terminal or "unknown",
                    "host": u.host or "localhost",
                    "started": u.started
                })
        except Exception:
            pass
        # Local Behavioral Heuristics (Anomalies)
        # Formato nuovo: dict strutturati con evidence (endpoint, conteggio,
        # processi possessori) — il brain li mappa su Alert.evidence cosi' il
        # pannello di dettaglio mostra I FATTI, non solo il tag. Il brain
        # accetta anche le stringhe dei vecchi agenti (backward compat).
        anomalies = []

        # 1. LOLBin Abuse & Crypto Miner Heuristics
        for p in processes:
            pname = p["name"].lower()
            if pname in ["certutil.exe", "bitsadmin.exe", "powershell.exe"] and p["memory_percent"] > 5.0:
                anomalies.append({
                    "type": "SUSPICIOUS_LOLBIN_MEMORY",
                    "process": p["name"],
                    "pid": p["pid"],
                    "memory_percent": round(p["memory_percent"], 1),
                })

            # CPU Spike + Miner Ports
            if p["cpu_percent"] > 80.0:
                miner_found = False
                miner_endpoint = ""
                for flow in network_flows:
                    if flow["pid"] == p["pid"]:
                        raddr = flow.get("raddr", "")
                        if ":3333" in raddr or ":4444" in raddr or ":14444" in raddr or ":14433" in raddr:
                            miner_found = True
                            miner_endpoint = raddr
                            break
                if miner_found:
                    anomalies.append({
                        "type": "POSSIBLE_CRYPTOMINER",
                        "process": p["name"],
                        "pid": p["pid"],
                        "endpoint": miner_endpoint,
                        "cpu_percent": round(p["cpu_percent"], 1),
                    })

        # 2. Network Beaconing
        dest_counts = {}
        for flow in network_flows:
            raddr = flow.get("raddr", "")
            if raddr:
                ip_only = raddr.split(":")[0]
                dest_counts.setdefault(ip_only, {"count": 0, "owners": {}})
                dest_counts[ip_only]["count"] += 1
                owner = next((p["name"] for p in processes if p["pid"] == flow["pid"]), None)
                if owner:
                    dest_counts[ip_only]["owners"][owner] = \
                        dest_counts[ip_only]["owners"].get(owner, 0) + 1

        for ip, info in dest_counts.items():
            if info["count"] >= 10 and not ip.startswith("127.") and not ip.startswith("192.168.") and not ip.startswith("10."):
                top_owners = sorted(info["owners"].items(), key=lambda kv: -kv[1])[:5]
                anomalies.append({
                    "type": "HIGH_CONNECTION_COUNT_TO_IP",
                    "ip": ip,
                    "connection_count": info["count"],
                    "processes": [{"name": n, "connections": c} for n, c in top_owners],
                })

        return {
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "ip_local": self._get_local_ip(),
            "ip_public": self._get_public_ip() if os.getenv("NODETRACE_PUBLIC_IP", "false").lower() in ("1", "true", "yes") else None,
            "geo_country": None,
            "geo_city": None,
            "processes": processes,
            "disk_free": disk_free,
            "disk_total": disk_total,
            "network_sent": network_sent,
            "network_received": network_received,
            "active_connections": active_connections,
            "network_flows": network_flows[:50], # Limit to 50 flows
            "users": users,
            "anomalies": anomalies
        }

    def _get_local_ip(self):
        # Try the standard socket trick first (uses default route)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                return ip
        except Exception:
            pass
        # Fallback: enumerate interfaces via psutil, pick first non-loopback IPv4
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return addr.address
        except Exception:
            pass
        return "127.0.0.1"

    def _get_public_ip(self):
        if time.time() - self._public_ip_at < 300:
            return self._public_ip
        try:
            from utils.curl_http import get as http_get
            response = http_get("https://api.ipify.org", timeout=5)
            self._public_ip = response.text if response.status_code == 200 else "unknown"
        except Exception:
            self._public_ip = "unknown"
        self._public_ip_at = time.time()
        return self._public_ip

    def get_system_info(self):
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "cpu_model": platform.processor(),
            "total_ram": int(psutil.virtual_memory().total / (1024 * 1024))  # MB
        }
