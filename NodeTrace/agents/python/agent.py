import json
import time
import requests
import os

from utils.logger import Logger
from services.telemetry import TelemetryService
from services.network import NetworkService
from services.token_service import TokenService
from services.retry_policy import retry

class Agent:
    def __init__(self):
        config_path = "config.json"
        if not os.path.exists(config_path):
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
            
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

        # Collect system info
        system_info = self.telemetry.get_system_info()

        payload = {
            "hostname": self.config["device_name"],
            "os": system_info["os"],
            "os_version": system_info["os_version"],
            "cpu_model": system_info["cpu_model"],
            "total_ram": system_info["total_ram"],
            "mac_address": network["mac"],
            "enroll_key": os.environ["AEGIS_ENROLL_KEY"],
        }

        r = requests.post(self.config["register_url"], json=payload)
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
        r = requests.post(self.config["update_url"], json=payload, headers=headers)
        # Silent by default as requested

    @retry(5, 1)
    def send_heartbeat(self, token, device_id):
        payload = {
            "device_id": device_id
        }

        headers = {"Authorization": f"Bearer {token}"}
        r = requests.post(self.config["heartbeat_url"], json=payload, headers=headers)

    @retry(5, 1)
    def fetch_commands(self, token, device_id):
        url = self.config["heartbeat_url"].replace("/heartbeat", "/commands")
        headers = {"Authorization": f"Bearer {token}"}
        params = {"device_id": device_id}
        try:
            r = requests.get(url, headers=headers, params=params, timeout=5)
            if r.status_code == 200:
                return r.json()
        except requests.RequestException as e:
            Logger.warn(f"Failed to fetch commands: {e}")
        return None

    def start(self):
        Logger.info("Starting NodeTrace Agent (Silent/Pull Mode)...")

        token, device_id = self.token_service.load()

        if not token:
            Logger.info("Registering device...")
            device = self.register()
            token = device["device_token"]
            device_id = device["device_id"]
            self.token_service.save(token, device_id)
            Logger.info("Device registered.")

        last_telemetry_time = 0
        telemetry_interval = self.config.get("telemetry_interval", 60)

        while True:
            current_time = time.time()

            # 1. Heartbeat (always send to keep alive)
            self.send_heartbeat(token, device_id)
            
            # 2. Check for commands
            command = self.fetch_commands(token, device_id)
            if command:
                cmd_type = command.get("command")
                if cmd_type == "GET_TELEMETRY":
                    Logger.info("Telemetry requested via command.")
                    self.send_telemetry(token, device_id)
                    last_telemetry_time = current_time  # Reset interval to prevent immediate re-send
                else:
                    Logger.info(f"Received unknown command: {cmd_type}")

            # 3. Occasional telemetry anyway (optional, maybe keep it very sparse)
            if current_time - last_telemetry_time > telemetry_interval:
                self.send_telemetry(token, device_id)
                last_telemetry_time = current_time

            time.sleep(self.config["heartbeat_interval"])

if __name__ == "__main__":
    Agent().start()
