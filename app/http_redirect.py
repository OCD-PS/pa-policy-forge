from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import os
from pathlib import Path
import urllib.parse

from app.certificates import CertificateError, configured_fqdn, normalize_fqdn


CONFIG_PATH = Path(os.getenv("PPF_APPLIANCE_CONFIG", "/data/appliance.json"))


def _incoming_host(value: str) -> str:
    value = str(value or "").strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise CertificateError("Ongeldige Host-header")
        candidate = value[1:end]
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise CertificateError("Ongeldige Host-header") from exc
    candidate = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    if candidate.lower() == "localhost":
        return "localhost"
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return normalize_fqdn(candidate)


def _allowed_redirect_hosts() -> set[str]:
    allowed: set[str] = set()
    for value in os.getenv("PPF_REDIRECT_ALLOWED_HOSTS", "").split(","):
        candidate = value.strip().lower().rstrip(".")
        if candidate:
            allowed.add(candidate)
    return allowed


def redirect_location(path: str, incoming_host: str, config_path: Path = CONFIG_PATH) -> str:
    host = configured_fqdn(config_path) or os.getenv("PPF_REDIRECT_FQDN", "").strip()
    if host:
        host = normalize_fqdn(host)
    else:
        host = _incoming_host(incoming_host)
        allowed_hosts = _allowed_redirect_hosts()
        if allowed_hosts:
            if host.lower() not in allowed_hosts:
                raise CertificateError("Host-header is niet toegestaan")
        elif host not in {"localhost"}:
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise CertificateError("Host-header is niet toegestaan") from exc
    if ":" in host:
        host = f"[{host}]"
    parsed = urllib.parse.urlsplit(path if str(path).startswith("/") else "/")
    safe_path = parsed.path or "/"
    if parsed.query:
        safe_path += "?" + parsed.query
    return f"https://{host}{safe_path}"


class RedirectHandler(BaseHTTPRequestHandler):
    server_version = "PA-Policy-Forge-Redirect"
    sys_version = ""

    def _redirect(self) -> None:
        try:
            location = redirect_location(self.path, self.headers.get("Host", ""))
        except CertificateError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Host header")
            return
        self.send_response(HTTPStatus.PERMANENT_REDIRECT)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _redirect
    do_HEAD = _redirect
    do_POST = _redirect
    do_PUT = _redirect
    do_PATCH = _redirect
    do_DELETE = _redirect
    do_OPTIONS = _redirect

    def log_message(self, _format: str, *_args) -> None:
        return


def main() -> None:
    port = int(os.getenv("PPF_REDIRECT_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), RedirectHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
