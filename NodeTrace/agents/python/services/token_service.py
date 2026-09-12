import json
import os
import time

class TokenService:
    FILE = os.getenv("NODETRACE_TOKEN_FILE", "token.json")

    def _atomic_write(self, data):
        parent = os.path.dirname(os.path.abspath(self.FILE))
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp_path = self.FILE + ".tmp"
        last_err = None
        for attempt in range(5):
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, self.FILE)
                return
            except (OSError, PermissionError) as e:
                last_err = e
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                time.sleep(0.2 * (attempt + 1))
        raise last_err

    def save(self, token, device_id, server_url=None):
        data = {"token": token, "device_id": device_id}
        if server_url:
            data["server_url"] = server_url
        self._atomic_write(data)

    def load(self):
        if not os.path.exists(self.FILE):
            return None, None
        for attempt in range(5):
            try:
                with open(self.FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data.get("token"), data.get("device_id")
            except json.JSONDecodeError:
                try:
                    os.remove(self.FILE)
                except OSError:
                    pass
                return None, None
            except (OSError, PermissionError):
                time.sleep(0.2 * (attempt + 1))
        return None, None

    def load_server(self):
        """URL server pinnato all'enrollment (None sui token legacy)."""
        try:
            with open(self.FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("server_url")
        except (OSError, ValueError):
            return None

    @staticmethod
    def check_server_pin(stored, current):
        """Come ServerPin Java: None se ok, altrimenti errore fatale."""
        current = (current or "").strip()
        if not current:
            return "register URL non configurato — refusing"
        if not stored or not str(stored).strip():
            return None  # legacy: pin da ora
        s = str(stored).strip().rstrip("/")
        c = current.rstrip("/")
        if s.lower() == c.lower():
            return None
        return (f"Server cambiato (stored={s} current={c}): "
                "re-enroll richiesto, rifiuto connessioni")
