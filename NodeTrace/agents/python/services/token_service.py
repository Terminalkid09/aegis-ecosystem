import json
import os

class TokenService:
    FILE = os.getenv("NODETRACE_TOKEN_FILE", "token.json")

    def save(self, token, device_id):
        parent = os.path.dirname(self.FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.FILE, "w") as f:
            json.dump({"token": token, "device_id": device_id}, f)

    def load(self):
        if not os.path.exists(self.FILE):
            return None, None
        with open(self.FILE, "r") as f:
            data = json.load(f)
            return data.get("token"), data.get("device_id")
