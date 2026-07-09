import json
import time
import os
import sys
import threading
import ctypes

from utils.logger import Logger
from utils.curl_http import get, post
from services.telemetry import TelemetryService
from services.network import NetworkService
from services.token_service import TokenService
from services.retry_policy import retry


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class PidLock:
    def __init__(self, pid_file: str):
        self.pid_file = pid_file

    def acquire(self):
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, "r", encoding="utf-8") as f:
                    old_pid = int(f.read().strip())
                if _pid_alive(old_pid):
                    Logger.error(f"NodeTrace agent already running (PID {old_pid})")
                    sys.exit(1)
            except (ValueError, OSError):
                pass
        parent = os.path.dirname(os.path.abspath(self.pid_file))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.pid_file, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

    def release(self):
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
        except OSError:
            pass


# ---------- Agent Class ----------

class Agent:
    def __init__(self):
        config_path = "config.json"
        for attempt in [
            config_path,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"),
        ]:
            if os.path.exists(attempt):
                config_path = attempt
                break
        else:
            try:
                import sys as _sys
                meipass = getattr(_sys, '_MEIPASS', None)
                if meipass:
                    p = os.path.join(meipass, "config.json")
                    if os.path.exists(p):
                        config_path = p
                    else:
                        p = os.path.join(os.path.dirname(meipass), "config.json")
                        if os.path.exists(p):
                            config_path = p
            except Exception:
                pass

        with open(config_path) as f:
            self.config = json.load(f)

        self.config["register_url"] = os.getenv("NODETRACE_REGISTER_URL", self.config["register_url"])
        self.config["update_url"] = os.getenv("NODETRACE_UPDATE_URL", self.config["update_url"])
        self.config["heartbeat_url"] = os.getenv("NODETRACE_HEARTBEAT_URL", self.config["heartbeat_url"])
        self.config["device_name"] = os.getenv("NODETRACE_DEVICE_NAME", self.config["device_name"])

        self.telemetry = TelemetryService()
        self.network = NetworkService()
        self.token_service = TokenService()

    @retry(5, 1)
    def register(self):
        network = self.network.get()

        system_info = self.telemetry.get_system_info()

        enroll_key = os.environ.get("AEGIS_ENROLL_KEY") or self.config.get("enroll_key")
        if not enroll_key:
            raise Exception("No enrollment key configured (set AEGIS_ENROLL_KEY or enroll_key in config.json)")

        payload = {
            "hostname": self.config["device_name"],
            "os": system_info["os"],
            "os_version": system_info["os_version"],
            "cpu_model": system_info["cpu_model"],
            "total_ram": system_info["total_ram"],
            "mac_address": network["mac"],
            "enroll_key": enroll_key,
        }

        r = post(self.config["register_url"], json_data=payload)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")

        return r.json()

    @retry(5, 1)
    def send_telemetry(self, token, device_id):
        telemetry = self.telemetry.get()

        payload = {
            "device_id": device_id,
            "cpu_usage": telemetry["cpu_usage"],
            "ram_usage": telemetry["ram_usage"],
            "ip_local": telemetry["ip_local"],
            "ip_public": telemetry["ip_public"],
            "geo_country": telemetry["geo_country"],
            "geo_city": telemetry["geo_city"],
            "processes": telemetry["processes"],
            "disk_free": telemetry["disk_free"],
            "disk_total": telemetry["disk_total"],
            "network_sent": telemetry["network_sent"],
            "network_received": telemetry["network_received"],
            "active_connections": telemetry["active_connections"],
            "users": telemetry.get("users", []),
            "network_flows": telemetry.get("network_flows", [])
        }

        headers = {"Authorization": f"Bearer {token}"}
        r = post(self.config["update_url"], json_data=payload, headers=headers)
        if r.status_code not in (200, 201):
            raise Exception(f"Telemetry update failed: HTTP {r.status_code}")

    @retry(5, 1)
    def send_heartbeat(self, token, device_id):
        payload = {"device_id": device_id}
        headers = {"Authorization": f"Bearer {token}"}
        r = post(self.config["heartbeat_url"], json_data=payload, headers=headers)
        if r.status_code not in (200, 201):
            raise Exception(f"Heartbeat failed: HTTP {r.status_code}")

    @retry(5, 1)
    def fetch_commands(self, token, device_id):
        url = self.config["heartbeat_url"].replace("/heartbeat", "/commands")
        headers = {"Authorization": f"Bearer {token}"}
        params = {"device_id": device_id}
        try:
            r = get(url, headers=headers, params=params, timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            Logger.warn(f"Failed to fetch commands: {e}")
        return None

    @retry(3, 1)
    def report_scan_results(self, token, device_id, cidr, scan_hosts):
        hb_url = self.config["heartbeat_url"]
        update_url = self.config["update_url"]

        api_base = hb_url.replace("/heartbeat", "").rstrip("/")
        scan_result_url = f"{api_base}/discovery/agent-scan-result"

        payload = {
            "cidr": cidr,
            "scan_hosts": scan_hosts,
        }
        headers = {"Authorization": f"Bearer {token}", "X-Agent-Id": device_id}

        try:
            r = post(scan_result_url, json_data=payload, headers=headers, timeout=10)
            if r.status_code == 200:
                Logger.info(f"Scan results reported: {len(scan_hosts)} hosts")
                return
            Logger.warn(f"Scan result POST got HTTP {r.status_code}, trying fallback...")
        except Exception as e:
            Logger.warn(f"Scan result POST failed: {e}, trying fallback...")

        try:
            r = post(update_url, json_data={
                "device_id": device_id,
                "scan_result": payload
            }, headers=headers, timeout=10)
            Logger.info(f"Scan results reported via telemetry (alt): {r.status_code}")
        except Exception as e:
            Logger.error(f"Failed to report scan results: {e}")

    def _run_network_scan(self, token, device_id, cidr, ports, probe_timeout=0.1):
        try:
            from utils.logger import Logger
            scan_results = self.network.scan_network(cidr=cidr, ports=ports, probe_timeout=probe_timeout)
            self.report_scan_results(token, device_id, cidr, scan_results)
            Logger.info(f"Network scan complete: {len(scan_results)} hosts found on {cidr}")
        except Exception as e:
            Logger.error(f"Network scan failed: {e}")

    def _execute_command(self, cmd_type, command):
        if cmd_type == "GET_TELEMETRY":
            Logger.info("Telemetry requested via command.")
            self.send_telemetry(self._token, self._device_id)
            self._last_telemetry_time = time.time()

        elif cmd_type == "NETWORK_SCAN":
            cidr = command.get("cidr", "192.168.1.0/24")
            ports = command.get("ports", [22, 80, 135, 139, 443, 445, 3389, 8000, 8080])
            probe_timeout = command.get("probe_timeout", 0.1)
            Logger.info(f"Network scan queued: {cidr}")
            threading.Thread(
                target=self._run_network_scan,
                args=(self._token, self._device_id, cidr, ports, probe_timeout),
                daemon=True
            ).start()

        else:
            Logger.info(f"Remediation command '{cmd_type}' ignored — NodeTrace is telemetry-only. Use Aegis-Guard for remediation.")

    def _probe_credentials(self, token, device_id):
        payload = {"device_id": device_id}
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = post(self.config["heartbeat_url"], json_data=payload, headers=headers, timeout=5)
            return r.status_code in (200, 201)
        except Exception:
            return False

    def _ensure_registered(self):
        token, device_id = self.token_service.load()

        if token and not self._probe_credentials(token, device_id):
            Logger.warn("Stored credentials are invalid (DB reset?). Re-registering...")
            self.token_service.clear()
            token, device_id = None, None

        while not token:
            try:
                Logger.info("Registering device...")
                device = self.register()
                token = device["device_token"]
                device_id = device["device_id"]
                self.token_service.save(token, device_id)
                Logger.info("Device registered.")
                return token, device_id
            except Exception as e:
                Logger.error(f"Registration failed: {e}. Retrying in 30s...")
                time.sleep(30)
                token, device_id = self.token_service.load()

        return token, device_id

    def start(self):
        Logger.info("Starting NodeTrace Agent (Silent/Pull Mode)...")

        token, device_id = self._ensure_registered()

        self._token = token
        self._device_id = device_id

        Logger.info("Sending initial telemetry...")
        try:
            self.send_telemetry(token, device_id)
            Logger.info("Initial telemetry sent.")
        except Exception as e:
            Logger.error(f"Initial telemetry failed: {e}")

        self._last_telemetry_time = time.time()
        telemetry_interval = self.config.get("telemetry_interval", 60)

        while True:
            try:
                current_time = time.time()

                self.send_heartbeat(token, device_id)

                command = self.fetch_commands(token, device_id)
                if command:
                    cmd_type = command.get("command")
                    if cmd_type:
                        self._execute_command(cmd_type, command)

                if current_time - self._last_telemetry_time > telemetry_interval:
                    self.send_telemetry(token, device_id)
                    self._last_telemetry_time = current_time
            except Exception as e:
                Logger.error(f"Agent loop error: {e}")

            time.sleep(self.config["heartbeat_interval"])


if __name__ == "__main__":
    token_file = TokenService.FILE
    token_dir = os.path.dirname(os.path.abspath(token_file)) or "."
    pid_file = os.path.join(token_dir, "nodetrace.pid")
    pid_lock = PidLock(pid_file)
    pid_lock.acquire()

    max_restarts = 5
    consecutive_restarts = 0

    try:
        while consecutive_restarts < max_restarts:
            try:
                Agent().start()
            except Exception as e:
                consecutive_restarts += 1
                Logger.error(f"Agent crashed ({consecutive_restarts}/{max_restarts}): {e}")
                if consecutive_restarts >= max_restarts:
                    Logger.error("Max consecutive restarts reached. Exiting.")
                    sys.exit(1)
                time.sleep(10)
    finally:
        pid_lock.release()
