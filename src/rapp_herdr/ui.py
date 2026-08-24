from __future__ import annotations

import json
import hmac
import secrets
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .backup import (
    MAX_BACKUP_BYTES,
    export_estate_backup,
    import_estate_backup,
)
from .estate import EstateManager, load_estate
from .model import RappHerdrError


class EstateStatusCache:
    def __init__(self, manifest: Path, ttl: float = 5.0):
        self.manifest = manifest
        self.ttl = ttl
        self._lock = threading.Lock()
        self._value: dict[str, Any] | None = None
        self._expires_at = 0.0

    def get(self, *, force: bool = False) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if not force and self._value is not None and now < self._expires_at:
                return self._value
            estate = load_estate(self.manifest)
            value = EstateManager(estate).run("status")
            value["observed_at"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            )
            self._value = value
            self._expires_at = now + self.ttl
            return value

    def export_backup(self) -> dict[str, Any]:
        with self._lock:
            return export_estate_backup(self.manifest)

    def import_backup(self, value: Any) -> dict[str, Any]:
        with self._lock:
            result = import_estate_backup(self.manifest, value)
            self._value = None
            self._expires_at = 0.0
            return result


def _html_path() -> Path:
    return Path(__file__).with_name("estate_ui.html")


def make_handler(
    cache: EstateStatusCache,
    *,
    token: str,
    allowed_hosts: set[str],
):
    class Handler(BaseHTTPRequestHandler):
        server_version = "rapp-herdr-ui/0.1"

        def _send(
            self,
            status: HTTPStatus,
            content_type: str,
            payload: bytes,
            *,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                return

        def _json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
            self._send(
                status,
                "application/json; charset=utf-8",
                (json.dumps(value, sort_keys=True) + "\n").encode(),
            )

        def _authorized(self) -> bool:
            parsed = urlparse(self.path)
            host = self.headers.get("Host", "")
            if host not in allowed_hosts:
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "error": "invalid dashboard authority"},
                )
                return False
            query_token = ""
            for part in parsed.query.split("&"):
                name, separator, value = part.partition("=")
                if separator and name == "token":
                    query_token = value
                    break
            supplied_token = self.headers.get("X-RAPP-Herdr-Token", "") or query_token
            if not hmac.compare_digest(supplied_token, token):
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "invalid dashboard token"},
                )
                return False
            return True

        def do_GET(self) -> None:
            if not self._authorized():
                return
            parsed = urlparse(self.path)
            path = parsed.path
            if path in {"/", "/index.html"}:
                try:
                    payload = _html_path().read_bytes()
                except OSError as exc:
                    self._json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"ok": False, "error": str(exc)},
                    )
                    return
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    payload,
                )
                return
            if path == "/api/health":
                self._json(HTTPStatus.OK, {"ok": True})
                return
            if path in {"/api/status", "/api/refresh"}:
                try:
                    value = cache.get(force=path == "/api/refresh")
                except RappHerdrError as exc:
                    self._json(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"ok": False, "error": str(exc)},
                    )
                    return
                self._json(HTTPStatus.OK, value)
                return
            if path == "/api/backup":
                try:
                    value = cache.export_backup()
                except RappHerdrError as exc:
                    self._json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"ok": False, "error": str(exc)},
                    )
                    return
                payload = (
                    json.dumps(value, ensure_ascii=False, indent=2) + "\n"
                ).encode("utf-8")
                stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                self._send(
                    HTTPStatus.OK,
                    "application/json; charset=utf-8",
                    payload,
                    extra_headers={
                        "Content-Disposition": (
                            "attachment; filename="
                            f'"rapp-herdr-estate-{stamp}.json"'
                        )
                    },
                )
                return
            self._json(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "not found"},
            )

        def do_POST(self) -> None:
            if not self._authorized():
                return
            path = urlparse(self.path).path
            if path != "/api/backup/import":
                self._json(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "not found"},
                )
                return
            content_type = self.headers.get("Content-Type", "")
            if content_type.split(";", 1)[0].strip() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"ok": False, "error": "backup import requires application/json"},
                )
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = -1
            if not 0 < content_length <= MAX_BACKUP_BYTES:
                self._json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"ok": False, "error": "backup exceeds the allowed size"},
                )
                return
            try:
                value = json.loads(self.rfile.read(content_length))
                result = cache.import_backup(value)
            except (UnicodeError, json.JSONDecodeError) as exc:
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": f"invalid backup JSON: {exc}"},
                )
                return
            except RappHerdrError as exc:
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": str(exc)},
                )
                return
            self._json(HTTPStatus.OK, result)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def run_ui(
    manifest: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
) -> int:
    if host not in {"127.0.0.1", "localhost"}:
        raise RappHerdrError(
            "estate UI is intentionally restricted to IPv4 loopback"
        )
    manifest_path = Path(manifest).expanduser().resolve()
    load_estate(manifest_path)
    cache = EstateStatusCache(manifest_path)
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(
            cache,
            token=token,
            allowed_hosts={
                f"127.0.0.1:{port}",
                f"localhost:{port}",
            },
        ),
    )
    actual_port = server.server_port
    server.RequestHandlerClass = make_handler(
        cache,
        token=token,
        allowed_hosts={
            f"127.0.0.1:{actual_port}",
            f"localhost:{actual_port}",
        },
    )
    address = f"http://{host}:{actual_port}/?token={token}"
    print(f"RAPP-Herdr estate UI: {address}", flush=True)
    if open_browser:
        webbrowser.open(address)
    try:
        server.serve_forever(poll_interval=0.25)
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
