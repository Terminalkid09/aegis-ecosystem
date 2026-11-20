"""Secret sources must resolve before Settings and never log values."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.core.secrets import load_vault_secrets, resolve_file_secrets


def test_file_secret_overrides_stale_environment(tmp_path):
    secret = tmp_path / "jwt"
    secret.write_text("new-secret-value\n", encoding="utf-8")
    env = {"JWT_SECRET": "stale", "JWT_SECRET_FILE": str(secret)}

    loaded = resolve_file_secrets(env)

    assert "JWT_SECRET" in loaded
    assert env["JWT_SECRET"] == "new-secret-value"
    assert env["JWT_SECRET_FILE"] == str(secret)


def test_secrets_directory_uses_variable_names(tmp_path):
    (tmp_path / "POSTGRES_PASSWORD").write_text("db-pass", encoding="utf-8")
    (tmp_path / "not a name").write_text("ignored", encoding="utf-8")
    env = {"AEGIS_SECRETS_DIR": str(tmp_path)}

    loaded = resolve_file_secrets(env)

    assert env["POSTGRES_PASSWORD"] == "db-pass"
    assert "not a name" not in env
    assert "POSTGRES_PASSWORD" in loaded


def test_empty_secret_file_is_a_startup_error(tmp_path):
    secret = tmp_path / "empty"
    secret.write_text("\n", encoding="utf-8")
    try:
        resolve_file_secrets({"JWT_SECRET_FILE": str(secret)})
    except RuntimeError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("empty secret accepted")


def _vault_server(payload: dict):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_vault_fills_missing_values_only():
    server = _vault_server({"data": {"data": {"JWT_SECRET": "from-vault", "AEGIS_API_KEY": "api-from-vault"}}})
    try:
        env = {
            "AEGIS_VAULT_ENABLED": "true",
            "AEGIS_VAULT_ADDR": f"http://127.0.0.1:{server.server_address[1]}",
            "AEGIS_VAULT_TOKEN": "test-token",
            "AEGIS_VAULT_PATH": "aegis",
            "JWT_SECRET": "explicit-wins",
        }
        loaded = load_vault_secrets(env)
        assert env["JWT_SECRET"] == "explicit-wins"
        assert env["AEGIS_API_KEY"] == "api-from-vault"
        assert set(loaded) == {"AEGIS_API_KEY"}
    finally:
        server.shutdown()
        server.server_close()
