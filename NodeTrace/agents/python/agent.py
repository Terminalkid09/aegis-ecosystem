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

    def _is_our_agent(self, pid: int) -> bool:
        """True se il pid e' davvero un'istanza di questo agent (audit: il
        solo kill(pid,0) e' vero anche per PID riciclati da altri processi)."""
        try:
            if sys.platform == "win32":
                return _pid_alive(pid) and self._cmdline_has(pid, "agent")
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().decode("utf-8", errors="ignore")
            return "agent" in os.path.basename(cmd.split("\x00")[0]).lower() or \
                "nodetrace" in cmd.lower()
        except (OSError, ValueError):
            return False

    @staticmethod
    def _cmdline_has(pid: int, needle: str) -> bool:
        # Windows: tasklist una tantum all'avvio (niente polling).
        try:
            import subprocess
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV"],
                capture_output=True, text=True, timeout=10).stdout.lower()
            return needle in out or "python" in out
        except Exception:
            return True  # fail-open solo qui: meglio doppio agent che nessun agent

    def acquire(self):
        parent = os.path.dirname(os.path.abspath(self.pid_file))
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Audit: O_CREAT|O_EXCL atomico (niente TOCTOU exists->write).
        try:
            fd = os.open(self.pid_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            try:
                with open(self.pid_file, "r", encoding="utf-8") as f:
                    old_pid = int(f.read().strip())
                if _pid_alive(old_pid) and self._is_our_agent(old_pid):
                    Logger.error(f"NodeTrace agent already running (PID {old_pid})")
                    sys.exit(1)
                Logger.warn(f"Stale/alien pid file (PID {old_pid}): sovrascrivo.")
            except (ValueError, OSError):
                pass
            with open(self.pid_file, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
            return
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

    def release(self):
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
        except OSError:
            pass


# ---------- Agent Class ----------

class Agent:
    AGENT_VERSION = os.getenv("NODETRACE_VERSION", "4.0.0")
    CAPABILITIES = {"telemetry": True, "network_scan": True, "update": True}

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
        # eBPF kernel stream (Linux, opt-in): collector esterno -> report eventi.
        # Disabilitato di default; richiede root/CAP_BPF + binari compilati.
        self.ebpf_enabled = os.getenv("NODETRACE_EBPF", str(
            self.config.get("ebpf_enabled", False))).lower() in ("1", "true", "yes")
        self.ebpf_collector = os.getenv(
            "NODETRACE_EBPF_COLLECTOR", self.config.get("ebpf_collector", ""))
        self.ebpf_obj = os.getenv(
            "NODETRACE_EBPF_OBJ", self.config.get("ebpf_obj", ""))
        self.ca_bundle = os.getenv("AEGIS_CA_BUNDLE", "")
        # Identità device mTLS (gap-closing): chiave nasce qui, cert dal SOC.
        token_dir = os.path.dirname(os.path.abspath(TokenService.FILE)) or "."
        self.identity_dir = os.getenv("NODETRACE_IDENTITY_DIR", token_dir)
        self._identity_b64 = None
        self._last_identity_check = 0.0
        self._last_cert_warn = 0.0
        if self.ebpf_enabled:
            self.CAPABILITIES = {**self.CAPABILITIES, "ebpf_process_events": True}

    def _agent_headers(self, token, device_id):
        """Header auth + X-Client-Cert quando l'identità esiste."""
        headers = {"Authorization": f"Bearer {token}", "X-Agent-Id": device_id}
        if self._identity_b64:
            headers["X-Client-Cert"] = self._identity_b64
        return headers

    def _brain_base(self):
        return self.config["heartbeat_url"].rsplit("/", 1)[0].rstrip("/")

    def _ensure_identity(self, token, device_id, force=False):
        """Bootstrap/rinnovo controllato: solo se assente o in scadenza.

        Mai overwrite di un'identità valida, mai eccezioni (log + degrado:
        il server applica comunque MTLS_MODE).
        """
        import time as _time
        now = _time.time()
        if not force and self._identity_b64 and now - self._last_identity_check < 3600:
            return True
        self._last_identity_check = now
        try:
            from services import device_identity as _di
            from utils import curl_http as _http
            key_pem, cert_pem = _di.load_identity(self.identity_dir)
            if not cert_pem or _di.needs_renewal(cert_pem):
                action = "rinnovo" if cert_pem else "bootstrap"
                Logger.info(f"Identità device: {action} CSR...")
                new_key, csr_pem = _di.build_csr(device_id)
                r = post(f"{self._brain_base()}/enroll/csr",
                         json_data={"csr_pem": csr_pem},
                         headers={"Authorization": f"Bearer {token}",
                                  "X-Agent-Id": device_id}, timeout=30)
                if r.status_code != 200:
                    Logger.warn(f"CSR rifiutata (HTTP {r.status_code}): {r.text[:200]}")
                    return False
                cert_pem = r.json()["certificate_pem"]
                _di.save_identity(self.identity_dir, new_key, cert_pem)
                Logger.info("Identità device emessa dal SOC.")
                key_pem = new_key
            _http.set_client_cert(os.path.join(self.identity_dir, "device.crt"),
                                  os.path.join(self.identity_dir, "device.key"))
            self._identity_b64 = _di.cert_b64der(cert_pem)
            return True
        except Exception as e:
            Logger.warn(f"Identità device non disponibile ({e}): senza mTLS")
            return False

    def _note_cert_problem(self, status_code):
        """401 con identità configurata: guida operatore, throttled, mai wipe."""
        import time as _time
        if status_code != 401 or not self._identity_b64:
            return
        now = _time.time()
        if now - self._last_cert_warn < 60:
            return
        self._last_cert_warn = now
        Logger.warn("401 con certificato device: possibile REVOCA o scadenza — "
                    "ricontrollare enrollment sul SOC (nessun wipe automatico)")

    @retry(5, 1)
    def register(self):
        network = self.network.get()

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
            "network_flows": telemetry.get("network_flows", []),
            "anomalies": telemetry.get("anomalies", []),
            "agent_version": self.AGENT_VERSION,
            "capabilities": self.CAPABILITIES,
        }

        headers = self._agent_headers(token, device_id)
        from utils.curl_http import ensure_ok
        r = post(self.config["update_url"], json_data=payload, headers=headers)
        ensure_ok(r, "telemetry")

    @retry(5, 1)
    def send_heartbeat(self, token, device_id):
        payload = {
            "device_id": device_id,
            "agent_version": self.AGENT_VERSION,
            "capabilities": self.CAPABILITIES,
        }
        if isinstance(getattr(self, "_sensor_summary", None), dict):
            payload["sensor"] = self._sensor_summary
        r = post(self.config["heartbeat_url"], json_data=payload,
                 headers=self._agent_headers(token, device_id))
        self._note_cert_problem(getattr(r, "status_code", 0))
        from utils.curl_http import ensure_ok
        ensure_ok(r, "heartbeat")

    def _ack_url(self):
        # Telemetry ack vive sotto /telemetry (auth X-Agent-Id + Bearer).
        return self.config["heartbeat_url"].replace("/heartbeat", "/telemetry/commands/ack")

    def _ack_command(self, token, device_id, command, status, details=None):
        # Best-effort: l'ack non deve mai rompere il loop agente.
        try:
            headers = self._agent_headers(token, device_id)
            post(self._ack_url(), json_data={
                "command": command, "status": status, "details": details,
            }, headers=headers, timeout=10)
        except Exception as e:
            Logger.warn(f"Command ack failed for {command}: {e}")

    @retry(5, 1)
    def fetch_commands(self, token, device_id):
        # Batch prima (drena fino a 50), singolo come fallback su brain vecchio.
        base = self.config["heartbeat_url"].replace("/heartbeat", "/commands")
        headers = self._agent_headers(token, device_id)
        try:
            r = get(base + "/batch", headers=headers,
                    params={"device_id": device_id, "n": 50}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    return data
        except Exception as e:
            Logger.warn(f"Failed to fetch command batch: {e}")
        try:
            r = get(base, headers=headers, params={"device_id": device_id}, timeout=5)
            if r.status_code == 200:
                single = r.json()
                return [single] if single else []
        except Exception as e:
            Logger.warn(f"Failed to fetch commands: {e}")
        return []

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
        headers = self._agent_headers(token, device_id)

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

    def _execute_command(self, cmd_type, command, token=None, device_id=None):
        if cmd_type == "GET_TELEMETRY":
            Logger.info("Telemetry requested via command.")
            self.send_telemetry(self._token, self._device_id)
            self._last_telemetry_time = time.time()
            if token and device_id:
                self._ack_command(token, device_id, cmd_type, "ok")

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
            if token and device_id:
                self._ack_command(token, device_id, cmd_type, "ok", f"scan started: {cidr}")

        elif cmd_type == "UPDATE_AGENT":
            if token and device_id:
                self._run_update(token, device_id, command)
            else:
                Logger.error("UPDATE_AGENT without auth context — refusing.")

        else:
            Logger.info(f"Remediation command '{cmd_type}' ignored — NodeTrace is telemetry-only. Use Aegis-Guard for remediation.")

    def _run_update(self, token, device_id, command):
        from services.updater import verify_signature, stage_package
        import tempfile
        import urllib.request
        import ssl
        cmd_name = "UPDATE_AGENT"
        url = command.get("url", "")
        sha = command.get("sha256", "")
        sig = command.get("signature", "")
        version = command.get("version", "latest")
        if not url or not sha or not sig:
            Logger.error("UPDATE_AGENT missing url/sha256/signature — refusing (fail-closed).")
            self._ack_command(token, device_id, cmd_name, "failed", "missing url/sha256/signature")
            return
        try:
            enroll_key = os.environ["AEGIS_ENROLL_KEY"]
        except KeyError:
            Logger.error("UPDATE_AGENT: AEGIS_ENROLL_KEY not set — refusing.")
            self._ack_command(token, device_id, cmd_name, "failed", "no enroll key")
            return
        if not verify_signature(sha, sig, enroll_key):
            Logger.error("UPDATE_AGENT bad signature — possible tampering, refusing.")
            self._ack_command(token, device_id, cmd_name, "failed", "bad signature")
            return
        # Audit SSRF: l'URL non e' coperto dalla firma — senza allowlist un
        # brain compromesso/MITM dirottava il download (con Bearer+cert!)
        # verso host arbitrari. Solo artefatti del brain pinnato.
        if not self._update_url_allowed(url):
            Logger.error("UPDATE_AGENT url fuori allowlist — refusing.")
            self._ack_command(token, device_id, cmd_name, "failed", "url not allowed")
            return
        # Manifest Ed25519 (M6 Fase 7): se il comando lo porta e la pubkey è
        # configurata, l'artefatto deve esserne coperto — altrimenti stop.
        from services.updater import verify_manifest_ed25519, manifest_covers
        _mpub = os.getenv("AEGIS_MANIFEST_PUBKEY", "").strip()
        _mani = command.get("manifest", "") or ""
        _msig = command.get("manifest_sig", "") or ""
        _fname = url.rsplit("/", 1)[-1] if "/" in url else url
        if _mpub:
            _v = verify_manifest_ed25519(_mani, _msig, _mpub) if _mani and _msig else False
            if _v is None:
                Logger.error("UPDATE_AGENT: manifest pubkey set ma cryptography assente — refusing.")
                self._ack_command(token, device_id, cmd_name, "failed", "manifest needs cryptography lib")
                return
            if not _v or not manifest_covers(_mani, _fname, sha):
                Logger.error("UPDATE_AGENT: manifest Ed25519 invalido o artefatto non coperto — refusing.")
                self._ack_command(token, device_id, cmd_name, "failed", "bad manifest")
                return
            Logger.info(f"UPDATE_AGENT: manifest Ed25519 verificato per {_fname}.")
        try:
            headers = dict(self._agent_headers(token, device_id))
            req = urllib.request.Request(url, headers=headers)
            ctx = ssl.create_default_context(cafile=self.ca_bundle or None)
            try:
                from services import device_identity as _di
                _kp, _cp = os.path.join(self.identity_dir, "device.key"), os.path.join(
                    self.identity_dir, "device.crt")
                if os.path.isfile(_kp) and os.path.isfile(_cp):
                    ctx.load_cert_chain(_cp, _kp)
            except Exception as e:
                Logger.warn(f"UPDATE_AGENT: client cert non caricato ({e})")
            import tempfile
            fd, tmp = tempfile.mkstemp(prefix="aegis-update-", suffix=".pkg")
            try:
                with urllib.request.urlopen(req, timeout=120, context=ctx) as resp, os.fdopen(fd, "wb") as f:
                    if resp.status not in (200,):
                        raise Exception(f"HTTP {resp.status}")
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                workdir = os.path.dirname(os.path.abspath(__file__))
                staged = stage_package(tmp, sha, workdir)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            Logger.info(f"UPDATE_AGENT v{version} staged at {staged} — restart agent to apply.")
            self._ack_command(token, device_id, cmd_name, "ok", f"staged v{version}")
        except Exception as e:
            Logger.error(f"UPDATE_AGENT failed: {e}")
            self._ack_command(token, device_id, cmd_name, "failed", str(e)[:500])

    def _brain_origin(self) -> str:
        """Origine (scheme://host:port) del brain da heartbeat_url."""
        import urllib.parse as _up
        try:
            p = _up.urlparse(self.config.get("heartbeat_url", ""))
            return f"{p.scheme}://{p.netloc}".rstrip("/").lower()
        except Exception:
            return ""

    def _update_url_allowed(self, url: str) -> bool:
        import urllib.parse as _up
        try:
            p = _up.urlparse(url or "")
            if p.scheme not in ("https", "http"):
                return False
            origin = f"{p.scheme}://{p.netloc}".rstrip("/").lower()
            if not origin or origin != self._brain_origin():
                return False
            return p.path.startswith("/api/v1/deploy/artifacts/")
        except Exception:
            return False

    def _ensure_registered(self):
        token, device_id = self.token_service.load()
        if token:
            # M6 Fase 7: pin del server — cambio silenzioso vietato.
            pin_err = TokenService.check_server_pin(
                self.token_service.load_server(), self.config["register_url"])
            stored = self.token_service.load_server()
            if pin_err and stored:
                raise RuntimeError(f"[FATAL] {pin_err}")

        while not token:
            try:
                Logger.info("Registering device...")
                device = self.register()
                token = device["device_token"]
                device_id = device["device_id"]
                self.token_service.save(token, device_id,
                                        server_url=self.config["register_url"])
                Logger.info("Device registered.")
                return token, device_id
            except Exception as e:
                Logger.error(f"Registration failed: {e}. Retrying in 30s...")
                time.sleep(30)
                token, device_id = self.token_service.load()

        return token, device_id

    def _report_url(self):
        return self.config["heartbeat_url"].replace("/heartbeat", "/telemetry/report")

    def _report_batch_url(self):
        return self.config["heartbeat_url"].replace("/heartbeat", "/telemetry/report/batch")

    def _forward_kernel_event(self, token, device_id, report):
        try:
            headers = self._agent_headers(token, device_id)
            r = post(self._report_url(), json_data=report, headers=headers, timeout=10)
            if r.status_code not in (200,):
                Logger.warn(f"Kernel event forward got HTTP {r.status_code}")
        except Exception as e:
            Logger.warn(f"Kernel event forward failed: {e}")

    def _flush_kernel_batch(self, token, device_id, batch):
        # Batch prima, singoli come fallback (niente eventi persi in silenzio).
        try:
            headers = self._agent_headers(token, device_id)
            r = post(self._report_batch_url(), json_data=batch, headers=headers, timeout=30)
            if r.status_code in (200,):
                return
            Logger.warn(f"Kernel batch got HTTP {r.status_code}, fallback singoli")
        except Exception as e:
            Logger.warn(f"Kernel batch failed: {e}, fallback singoli")
        for rep in batch:
            self._forward_kernel_event(token, device_id, rep)

    def _run_ebpf_stream(self, token, device_id):
        """Legge lo stdout del collector eBPF e inoltra ogni evento al brain."""
        import subprocess
        from services.ebpf import parse_line, event_to_report, collector_cmd
        if sys.platform != "linux":
            Logger.error("eBPF stream solo su Linux.")
            return
        if not self.ebpf_collector or not os.path.exists(self.ebpf_collector):
            Logger.error("eBPF collector non trovato — disabilitato.")
            return
        from services.ebpf import KernelEventBatcher, SeenCache
        seen = SeenCache()
        restart_delay = 1
        for attempt in range(1, 6):
            proc = None
            try:
                proc = subprocess.Popen(
                    collector_cmd(self.ebpf_collector, self.ebpf_obj or None),
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, bufsize=1,
                )
                Logger.info(f"eBPF kernel stream attivo (attempt {attempt}).")
                batcher = KernelEventBatcher(max_n=25, max_age_s=2.0)
                net = self.network.get()
                for line in proc.stdout:
                    ev = parse_line(line)
                    if not ev or seen.check(ev):
                        continue
                    report = event_to_report(
                        ev, device_id,
                        hostname=self.config.get("device_name"),
                        ip_local=(net.get("ip") if isinstance(net, dict) else None),
                        agent_version=self.AGENT_VERSION,
                        default_provenance="ebpf-full",
                    )
                    if batcher.add(report):
                        self._flush_kernel_batch(token, device_id, batcher.drain())
                if len(batcher):
                    self._flush_kernel_batch(token, device_id, batcher.drain())
                if proc.returncode == 0:
                    Logger.warn("eBPF collector exited cleanly; no restart needed.")
                    return
                Logger.warn(f"eBPF collector exited with code {proc.returncode}; restarting.")
            except Exception as e:
                Logger.error(f"eBPF stream interrotto: {e}")
            finally:
                if proc is not None:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
            time.sleep(restart_delay)
            restart_delay = min(restart_delay * 2, 30)
        Logger.error("eBPF collector disabled after repeated failures.")

    def _run_auditd_stream(self, token, device_id, audit_log):
        """Fallback mirato (M3 Fase 4): solo exec da auditd, mai duplicatore.

        Attivo solo con NODETRACE_AUDITD=1 e eBPF spento. Poll ogni 5 s,
        batch come lo stream eBPF.
        """
        from services.auditd import AuditdTailer
        from services.ebpf import event_to_report, KernelEventBatcher, SeenCache
        if sys.platform != "linux":
            return
        Logger.info(f"auditd fallback attivo su {audit_log} (solo exec).")
        tailer = AuditdTailer(audit_log)
        batcher = KernelEventBatcher(max_n=25, max_age_s=5.0)
        seen = SeenCache()
        net = self.network.get()
        while True:
            try:
                for ev in tailer.poll():
                    if seen.check(ev):
                        continue
                    report = event_to_report(
                        ev, device_id,
                        hostname=self.config.get("device_name"),
                        ip_local=(net.get("ip") if isinstance(net, dict) else None),
                        agent_version=self.AGENT_VERSION,
                    )
                    if batcher.add(report):
                        self._flush_kernel_batch(token, device_id, batcher.drain())
                if len(batcher):
                    self._flush_kernel_batch(token, device_id, batcher.drain())
            except Exception as e:
                Logger.error(f"auditd stream interrotto: {e}")
            time.sleep(5)

    def start(self):
        Logger.info("Starting NodeTrace Agent (Silent/Pull Mode)...")

        token, device_id = self._ensure_registered()

        self._token = token
        self._device_id = device_id

        # Identità device mTLS: bootstrap controllato post-registration.
        self._ensure_identity(token, device_id)

        if self.ebpf_enabled:
            threading.Thread(
                target=self._run_ebpf_stream,
                args=(token, device_id),
                daemon=True,
                name="ebpf-stream",
            ).start()
        else:
            Logger.info("eBPF stream disabilitato (polling + scan attivi).")

        # Probe kernel all'avvio (M3 Fase 4): profilo + fallback dichiarati.
        self._sensor_mode = "unavailable"
        self._sensor_summary = {}
        try:
            from services.linux_probe import probe as _kprobe, auditd_available as _auditd_ok
            from services.linux_probe import sensor_mode as _sensor_mode
            _prof = _kprobe()
            Logger.info(f"Kernel profile: {_prof.get('profile')} ({_prof.get('reason') or 'ok'})")
            _auditd = _auditd_ok()
            if _auditd:
                Logger.info(f"auditd disponibile: {_auditd}")
            # Fallback auditd mirato: solo se eBPF spento e auditd presente.
            _auditd_on = os.getenv("NODETRACE_AUDITD", str(
                self.config.get("auditd_enabled", False))).lower() in ("1", "true", "yes")
            _auditd_active = bool(_auditd and not self.ebpf_enabled and _auditd_on)
            import sys as _sys
            self._sensor_mode = _sensor_mode(
                _sys.platform, self.ebpf_enabled, _auditd_active)
            self.CAPABILITIES = {**self.CAPABILITIES,
                                 "sensor_mode": self._sensor_mode,
                                 "kernel_profile": _prof.get("profile"),
                                 "kernel_reason": _prof.get("reason") or ""}
            try:
                from services import linux_evidence as _ev
                _snap = _ev.collect()
                self._sensor_summary = {
                    "mode": self._sensor_mode,
                    "units": _snap.get("unit_count", 0),
                    "ssh_keys": len(_snap.get("ssh_keys", [])),
                    "capabilities": _snap.get("capabilities", [])[:12],
                    "container": _snap.get("container", False),
                    "degraded": _snap.get("degraded", []),
                }
                Logger.info("Evidence snapshot: %(units)d unit, %(keys)d ssh host con chiavi, "
                            "caps=%(caps)s degraded=%(deg)s" % {
                                "units": self._sensor_summary["units"],
                                "keys": self._sensor_summary["ssh_keys"],
                                "caps": ",".join(self._sensor_summary["capabilities"][:6]),
                                "deg": self._sensor_summary["degraded"] or "nessuno"})
            except Exception as e:
                Logger.warn(f"Evidence snapshot fallita: {e}")
            if _auditd_active:
                threading.Thread(
                    target=self._run_auditd_stream,
                    args=(token, device_id, _auditd),
                    daemon=True,
                    name="auditd-stream",
                ).start()
        except Exception as e:
            Logger.warn(f"Kernel probe fallita: {e}")

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

                self._ensure_identity(token, device_id)  # throttled oraria dentro
                self.send_heartbeat(token, device_id)

                # Drain adattivo: se il batch torna pieno, ripolla subito
                # (max 5 giri per ciclo per non affamare telemetria/heartbeat).
                for _ in range(5):
                    commands = self.fetch_commands(token, device_id)
                    if not commands:
                        break
                    for command in commands:
                        cmd_type = (command or {}).get("command")
                        if cmd_type:
                            self._execute_command(cmd_type, command, token, device_id)
                    if len(commands) < 50:
                        break

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
