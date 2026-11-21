"""Resolve deployment secrets before Pydantic reads the environment.

Two mechanisms are supported, in this order:

1. Files: every ``NAME_FILE`` variable points to a file whose content becomes
   ``NAME``. ``AEGIS_SECRETS_DIR`` loads a directory of files named after the
   environment variables (the Docker/Kubernetes secrets pattern).
2. HashiCorp Vault KV v2, opt-in with ``AEGIS_VAULT_ENABLED=true``. Vault only
   fills variables that are still missing, so an explicit environment value
   keeps the usual 12-factor precedence.

No secret is ever logged or included in an exception message. A missing or
unreadable explicitly configured secret source is a startup error, not a
silent fallback to a default.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import MutableMapping
from pathlib import Path

_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_TRUE = {"1", "true", "yes", "on"}


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def _valid_name(name: str) -> bool:
    return bool(_ENV_NAME.fullmatch(name or ""))


def _read_secret(path: str, source: str) -> str:
    file_path = Path(path)
    try:
        if not file_path.is_file():
            raise OSError("not a regular file")
        value = file_path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        # Do not include file contents or the exception's path in logs; the
        # operator already knows which source was configured.
        raise RuntimeError(f"secret source {source} is not readable") from exc
    if not value:
        raise RuntimeError(f"secret source {source} is empty")
    return value


def resolve_file_secrets(environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Load ``*_FILE`` and ``AEGIS_SECRETS_DIR`` into the environment.

    Returns the names that were loaded (never their values). File sources win
    over an already-present plain variable: mounting a secret is an explicit
    deployment decision and must not be silently ignored because a stale value
    remains in the process environment.
    """
    env = os.environ if environ is None else environ
    loaded: list[str] = []

    secrets_dir = (env.get("AEGIS_SECRETS_DIR") or "").strip()
    if secrets_dir:
        root = Path(secrets_dir)
        if not root.is_dir():
            raise RuntimeError("AEGIS_SECRETS_DIR is not a directory")
        for child in sorted(root.iterdir()):
            if not child.is_file() or not _valid_name(child.name):
                continue
            env[child.name] = _read_secret(str(child), f"AEGIS_SECRETS_DIR/{child.name}")
            loaded.append(child.name)

    for key in sorted(env.keys()):
        if not key.endswith("_FILE"):
            continue
        target = key[:-5]
        if not _valid_name(target):
            continue
        env[target] = _read_secret(env[key], key)
        loaded.append(target)

    return loaded


def _vault_token(env: MutableMapping[str, str]) -> str:
    token = (env.get("AEGIS_VAULT_TOKEN") or "").strip()
    if token:
        return token
    token_file = (env.get("AEGIS_VAULT_TOKEN_FILE") or "").strip()
    if token_file:
        return _read_secret(token_file, "AEGIS_VAULT_TOKEN_FILE")
    raise RuntimeError("AEGIS_VAULT_ENABLED=true requires AEGIS_VAULT_TOKEN or AEGIS_VAULT_TOKEN_FILE")


def _vault_context(env: MutableMapping[str, str]) -> ssl.SSLContext:
    cafile = (env.get("AEGIS_VAULT_CACERT") or "").strip() or None
    try:
        context = ssl.create_default_context(cafile=cafile)
    except OSError as exc:
        raise RuntimeError("AEGIS_VAULT_CACERT is not a readable CA file") from exc
    if _enabled(env.get("AEGIS_VAULT_SKIP_VERIFY")):
        # Explicit lab-only escape hatch for a self-signed Vault certificate.
        # The context is still created by the normal verified constructor; only
        # this opt-in changes verification, so no unverified-context helper is
        # needed.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def load_vault_secrets(environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Load a KV v2 secret map from Vault, filling only missing variables."""
    env = os.environ if environ is None else environ
    if not _enabled(env.get("AEGIS_VAULT_ENABLED")):
        return []

    addr = (env.get("AEGIS_VAULT_ADDR") or "").strip().rstrip("/")
    if not addr:
        raise RuntimeError("AEGIS_VAULT_ENABLED=true requires AEGIS_VAULT_ADDR")
    mount = (env.get("AEGIS_VAULT_MOUNT") or "secret").strip().strip("/")
    path = (env.get("AEGIS_VAULT_PATH") or "aegis").strip().strip("/")
    if not mount or not path:
        raise RuntimeError("AEGIS_VAULT_MOUNT and AEGIS_VAULT_PATH must not be empty")

    url = f"{addr}/v1/{urllib.parse.quote(mount, safe='')}/data/{urllib.parse.quote(path, safe='/')}"
    headers = {
        "X-Vault-Token": _vault_token(env),
        "Accept": "application/json",
    }
    namespace = (env.get("AEGIS_VAULT_NAMESPACE") or "").strip()
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    parsed_addr = urllib.parse.urlparse(addr)
    if parsed_addr.scheme not in ("http", "https") or not parsed_addr.netloc:
        raise RuntimeError("AEGIS_VAULT_ADDR must be an http(s) URL")

    request = urllib.request.Request(url, headers=headers, method="GET")
    timeout = float((env.get("AEGIS_VAULT_TIMEOUT_S") or "10").strip() or "10")
    try:
        # The URL is assembled only from the validated HTTP(S) address above and
        # quoted mount/path components; file:, data: and custom schemes are
        # rejected before this call. B310 is suppressed with that invariant.
        with urllib.request.urlopen(  # nosec B310
                request, timeout=timeout, context=_vault_context(env)) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Vault KV request failed with HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise RuntimeError("Vault KV request failed") from exc

    data = (payload.get("data") or {}).get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise TypeError("Vault response has no data.data object")

    loaded: list[str] = []
    override = _enabled(env.get("AEGIS_VAULT_OVERRIDE"))
    for key, value in data.items():
        if not _valid_name(key) or value is None:
            continue
        if not override and (env.get(key) or "").strip():
            continue
        if isinstance(value, (dict, list)):
            env[key] = json.dumps(value, separators=(",", ":"))
        else:
            env[key] = str(value)
        loaded.append(key)
    return loaded


def apply_secret_sources() -> list[str]:
    """Apply every configured source once, before Settings is constructed."""
    return resolve_file_secrets() + load_vault_secrets()
