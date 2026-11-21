"""HTTP deception with realistic virtual hosts and response profiles.

The listener is still passive (it never proxies or executes code), but it no
longer answers every request with the same ``It works!`` page.  Unknown hosts
get an Apache-style default page, known vhosts get a plausible application and
common reconnaissance paths return the status a real deployment would return.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Optional

from loguru import logger

from app.core.config import settings
from honeypot.sensors.ssh_sensor import _post_ingest

_SERVER = "Apache/2.4.57 (Ubuntu)"


def _page(title: str, body: str, extra_head: str = "") -> bytes:
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        f"<title>{title}</title>\n{extra_head}"
        "</head>\n<body>\n"
        f"{body}\n"
        "</body>\n</html>\n"
    ).encode("utf-8")


def _default_page() -> bytes:
    return _page(
        "Apache2 Ubuntu Default Page: It works",
        "<h1>Apache2 Ubuntu Default Page</h1>\n"
        "<p>This is the default welcome page used to test the correct "
        "operation of the Apache2 server after installation on Ubuntu systems.</p>\n"
        "<p><b>It works!</b></p>",
    )


def _portal(host: str) -> bytes:
    return _page(
        "Acme Intranet",
        "<div class=\"header\"><h1>Acme Intranet</h1></div>\n"
        "<p>Internal collaboration portal. Authorized users only.</p>\n"
        "<form method=\"post\" action=\"/login\">\n"
        "  <label>Username <input name=\"username\" autocomplete=\"username\"></label>\n"
        "  <label>Password <input type=\"password\" name=\"password\"></label>\n"
        "  <button type=\"submit\">Sign in</button>\n"
        "</form>\n"
        f"<p class=\"muted\">Server: {host}</p>",
        "<link rel=\"stylesheet\" href=\"/assets/site.css\">\n",
    )


def _owa() -> bytes:
    return _page(
        "Outlook Web App",
        "<div id=\"owa\"><h1>Outlook Web App</h1>\n"
        "<p>Sign in to your mailbox.</p>\n"
        "<form method=\"post\" action=\"/owa/auth.owa\">"
        "<input name=\"username\" placeholder=\"Domain\\user name\">"
        "<input type=\"password\" name=\"password\" placeholder=\"Password\">"
        "<button>Sign in</button></form></div>",
        "<meta name=\"generator\" content=\"Microsoft Exchange Server 2019\">\n",
    )


def _remote() -> bytes:
    return _page(
        "Remote Desktop Web Access",
        "<h1>Remote Desktop Web Access</h1>\n"
        "<p>Use your domain credentials to access published desktops.</p>\n"
        "<form method=\"post\" action=\"/RDWeb/Pages/en-US/login.aspx\">"
        "<input name=\"DomainUserName\" placeholder=\"CORP\\user\">"
        "<input type=\"password\" name=\"UserPass\" placeholder=\"Password\">"
        "<button>Sign in</button></form>",
    )


class HTTPSensor:
    def __init__(self, host: str = "0.0.0.0", port: int | None = None):
        self.host = host
        self.port = port or settings.HTTP_SENSOR_PORT

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        attacker_ip, attacker_port = peer[0], peer[1]
        session_id = str(uuid.uuid4())
        logger.info(f"[HTTP] {attacker_ip}:{attacker_port} — session {session_id}")

        raw = ""
        try:
            raw = (await asyncio.wait_for(reader.read(8192), timeout=5.0)).decode(errors="ignore")
        except (asyncio.TimeoutError, ConnectionResetError):
            pass

        method, path, headers, body = self._parse_request(raw)
        status, response_headers, response_body = self._response(method, path, headers)
        response_headers = {
            "Server": _SERVER,
            "Date": formatdate(usegmt=True),
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Length": str(len(response_body)),
            "Connection": "close",
            **response_headers,
        }
        try:
            head = f"HTTP/1.1 {status} {self._reason(status)}\r\n"
            head += "".join(f"{key}: {value}\r\n" for key, value in response_headers.items())
            if isinstance(response_body, str):
                response_body = response_body.encode("utf-8")
            writer.write(head.encode("utf-8") + b"\r\n" + response_body)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        commands = []
        if method and path:
            commands.append(f"{method} {path}")
        for name in ("Host", "User-Agent", "X-Forwarded-For"):
            if headers.get(name):
                commands.append(f"{name}: {headers[name][:256]}")
        if body:
            commands.append(f"body[{len(body)}]={body[:256]!r}")
        await self._report(session_id, attacker_ip, attacker_port, commands)

    def _parse_request(self, raw: str):
        method = path = None
        headers: dict[str, str] = {}
        body = b""
        head, _, body_text = raw.partition("\r\n\r\n")
        lines = head.splitlines()
        if lines:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method, path = parts[0][:16], parts[1][:512]
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep:
                headers[key.strip()] = value.strip()
        body = body_text.encode("utf-8", "ignore")
        return method, path, headers, body

    def _response(self, method: Optional[str], path: Optional[str], headers: dict[str, str]):
        if not method or not path:
            return 400, {"Content-Type": "text/html"}, _page("400 Bad Request", "<h1>Bad Request</h1>")
        if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
            return 405, {"Content-Type": "text/html", "Allow": "GET, HEAD, POST, OPTIONS"}, _page(
                "405 Method Not Allowed", "<h1>Method Not Allowed</h1>"
            )

        host = (headers.get("Host") or "").split(":", 1)[0].lower()
        clean_path = path.split("?", 1)[0]

        if clean_path == "/robots.txt":
            return 200, {"Content-Type": "text/plain; charset=utf-8"}, (
                b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /owa/\n"
            )
        if clean_path in {"/.env", "/config.php", "/backup.zip", "/db.sql"}:
            return 404, {"Content-Type": "text/html"}, _page(
                "404 Not Found", "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>"
            )
        if clean_path in {"/server-status", "/server-info"}:
            return 403, {"Content-Type": "text/html"}, _page(
                "403 Forbidden", "<h1>Forbidden</h1><p>You don't have permission to access this resource.</p>"
            )
        if clean_path.startswith("/owa"):
            return 200, {"Content-Type": "text/html; charset=utf-8", "X-Powered-By": "ASP.NET"}, _owa()
        if clean_path.startswith("/RDWeb") or clean_path.startswith("/remote"):
            return 200, {"Content-Type": "text/html; charset=utf-8"}, _remote()
        if clean_path in {"/login", "/admin", "/admin/", "/portal"}:
            return 200, {"Content-Type": "text/html; charset=utf-8"}, _portal(host or "intranet")
        if clean_path == "/phpinfo.php":
            return 200, {"Content-Type": "text/html; charset=utf-8", "X-Powered-By": "PHP/8.1.2-1ubuntu2.14"}, _page(
                "phpinfo()",
                "<h1>PHP Version 8.1.2-1ubuntu2.14</h1>"
                "<table><tr><td>System</td><td>Linux ubuntu 5.15.0-91-generic</td></tr>"
                "<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr></table>",
            )
        if clean_path == "/wp-login.php":
            return 200, {"Content-Type": "text/html; charset=utf-8"}, _page(
                "WordPress &rsaquo; Log In",
                "<h1>WordPress</h1><form method=\"post\" action=\"/wp-login.php\">"
                "<input name=\"log\" placeholder=\"Username\">"
                "<input type=\"password\" name=\"pwd\" placeholder=\"Password\">"
                "<button>Log In</button></form>",
            )
        if clean_path in {"/", "/index.html", "/index.php"}:
            if host in {"intranet.acme.local", "portal.acme.local"}:
                return 200, {"Content-Type": "text/html; charset=utf-8"}, _portal(host)
            return 200, {"Content-Type": "text/html; charset=utf-8"}, _default_page()
        return 404, {"Content-Type": "text/html"}, _page(
            "404 Not Found",
            "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>"
            "<hr><address>Apache/2.4.57 (Ubuntu) Server at "
            f"{host or 'localhost'} Port 80</address>",
        )

    @staticmethod
    def _reason(status: int) -> str:
        return {
            200: "OK", 400: "Bad Request", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed",
        }.get(status, "OK")

    async def _report(self, session_id, ip, port, commands):
        await _post_ingest({
            "sensor_type": "http", "attacker_ip": ip,
            "attacker_port": port, "sensor_port": self.port,
            "session_id": session_id, "commands": commands,
        })

    async def start(self):
        server = await asyncio.start_server(self.handle, self.host, self.port)
        logger.info(f"[HTTP Sensor] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
