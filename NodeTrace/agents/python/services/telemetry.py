import psutil
import platform
import time
import shutil
import socket

class TelemetryService:
    start_time = time.time()

    def get(self):
        cpu_usage = psutil.cpu_percent()
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

        procs = sorted(psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_percent']), key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:10]
        processes = []
        for p in procs:
            try:
                pinfo = p.info
                processes.append({
                    "name": pinfo['name'] or 'unknown',
                    "pid": pinfo['pid'],
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

        return {
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "ip_local": self._get_local_ip(),
            "ip_public": self._get_public_ip(),
            "geo_country": None,
            "geo_city": None,
            "processes": processes,
            "disk_free": disk_free,
            "disk_total": disk_total,
            "network_sent": network_sent,
            "network_received": network_received,
            "active_connections": active_connections,
            "network_flows": network_flows[:50], # Limit to 50 flows
            "users": users
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
        try:
            from utils.curl_http import get as http_get
            response = http_get("https://api.ipify.org", timeout=5)
            return response.text if response.status_code == 200 else "unknown"
        except Exception:
            return "unknown"

    def get_system_info(self):
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "cpu_model": platform.processor(),
            "total_ram": int(psutil.virtual_memory().total / (1024 * 1024))  # MB
        }