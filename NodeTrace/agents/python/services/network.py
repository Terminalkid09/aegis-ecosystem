import socket
import uuid
import psutil
from utils.curl_http import get as http_get

class NetworkService:
    def get(self):
        iface = psutil.net_if_addrs()
        gws = psutil.net_if_stats()

        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        if local_ip.startswith("127."):
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        local_ip = addr.address
                        break
                if not local_ip.startswith("127."):
                    break
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                        for ele in range(0,8*6,8)][::-1])

        try:
            public_ip = http_get("https://api.ipify.org", timeout=5).text
        except Exception:
            public_ip = None

        return {
            "local_ip": local_ip,
            "public_ip": public_ip,
            "mac": mac,
            "gateway": None,
            "dns": None,
            "iface": list(iface.keys())[0] if iface else None
        }

    def scan_network(self, cidr="192.168.1.0/24", ports=None, probe_timeout=0.2):
        """Perform network scan from this host using ping sweep + ARP + TCP.

        Args:
            cidr: Subnet to scan (e.g. "192.168.1.0/24")
            ports: List of TCP ports to check
            probe_timeout: Seconds to wait per ping probe.
        """
        import subprocess
        import ipaddress
        import re
        import concurrent.futures
        import time

        results = []
        if ports is None:
            ports = [22, 80, 135, 139, 443, 445, 3389, 8000, 8080]

        try:
            target_net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            target_net = ipaddress.ip_network("192.168.1.0/24", strict=False)

        all_hosts = list(target_net.hosts())
        EXCLUDE = {str(target_net.network_address), str(target_net.broadcast_address)}
        probe_ips = [str(ip) for ip in all_hosts if str(ip) not in EXCLUDE]

        # Phase 1: Ping sweep to discover live hosts
        live_ips = set()

        def _ping(ip):
            try:
                code = subprocess.run(
                    ["ping", "-n", "1", "-w", str(int(probe_timeout * 1000)), ip],
                    capture_output=True, timeout=5
                ).returncode
                if code == 0:
                    return ip
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            for result in pool.map(_ping, probe_ips):
                if result:
                    live_ips.add(result)

        # Phase 2: Read ARP table to get MAC addresses of live hosts
        def _read_arp():
            entries = {}
            try:
                out = subprocess.check_output("arp -a", shell=True, timeout=5).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                        ip = parts[0]
                        mac_str = parts[1].replace("-", ":") if "-" in parts[1] else parts[1]
                        if mac_str.count(":") == 5 and mac_str != "00:00:00:00:00:00":
                            entries[ip] = mac_str.upper()
            except Exception:
                pass
            return entries

        arp_entries = _read_arp()

        # Phase 3: Collect live hosts (ping responders or ARP entries in our subnet)
        filtered_ips = []
        for ip in sorted(live_ips):
            try:
                addr = ipaddress.ip_address(ip)
                if addr in target_net and not addr.is_multicast and not addr.is_reserved:
                    filtered_ips.append(ip)
            except Exception:
                pass
        # Also add any ARP-only hosts (responded to ARP but not ping)
        for ip, mac in arp_entries.items():
            if ip not in live_ips:
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr in target_net and not addr.is_multicast and not addr.is_reserved:
                        filtered_ips.append(ip)
                except Exception:
                    pass

        # Phase 4: Parallel port check on discovered IPs
        def _check_ports(ip):
            open_ports = []
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                    s.close()
                except Exception:
                    pass
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            return {
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": arp_entries.get(ip),
                "open_ports": open_ports,
                "os_guess": "windows" if (3389 in open_ports or 445 in open_ports or 135 in open_ports) else ("linux" if 22 in open_ports else ("network-service" if len(open_ports) > 0 else "unknown")),
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(_check_ports, sorted(set(filtered_ips))))

        return results