from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError

from rapp_herdr.model import RappHerdrError
from rapp_herdr.ui import EstateStatusCache, _html_path, make_handler, run_ui
from tests.test_estate import create_estate


class FakeCache:
    def get(self, *, force=False):
        return {
            "ok": True,
            "estate": "Test Estate",
            "observed_at": "2026-08-23T00:00:00Z",
            "devices": [],
            "forced": force,
        }


class UiTests(unittest.TestCase):
    def test_ui_contains_required_theme_contract(self) -> None:
        html = _html_path().read_text(encoding="utf-8")

        self.assertIn('new URLSearchParams(window.location.search).get("scoutTheme")', html)
        self.assertIn("--cp-bg: #f7f4ef;", html)
        self.assertIn("--cp-accent: #b11f4b;", html)
        self.assertIn('font-family: "Segoe UI", Aptos, Calibri', html)
        self.assertNotIn("<script src=", html)
        self.assertIn('id="exportBackupButton"', html)
        self.assertIn('id="importBackupButton"', html)

    def test_ui_serves_html_and_live_status(self) -> None:
        token = "test-token"
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        host = f"127.0.0.1:{server.server_port}"
        server.RequestHandlerClass = make_handler(
            FakeCache(),
            token=token,
            allowed_hosts={host},
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with urllib.request.urlopen(
                base + "/?token=" + token,
                timeout=3,
            ) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(b"RAPP-Herdr Estate", response.read())
            request = urllib.request.Request(
                base + "/api/refresh",
                headers={"X-RAPP-Herdr-Token": token},
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                value = json.loads(response.read())
                self.assertTrue(value["ok"])
                self.assertTrue(value["forced"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_ui_rejects_wrong_host_and_missing_token(self) -> None:
        token = "test-token"
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        host = f"127.0.0.1:{server.server_port}"
        server.RequestHandlerClass = make_handler(
            FakeCache(),
            token=token,
            allowed_hosts={host},
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                urllib.request.urlopen(base + "/api/status", timeout=3)
                self.fail("missing dashboard token was accepted")
            except HTTPError as missing:
                self.assertEqual(missing.code, 401)
                missing.close()
            request = urllib.request.Request(
                base + "/api/status",
                headers={
                    "Host": "attacker.example",
                    "X-RAPP-Herdr-Token": token,
                },
            )
            try:
                urllib.request.urlopen(request, timeout=3)
                self.fail("rebound Host header was accepted")
            except HTTPError as rebound:
                self.assertEqual(rebound.code, 403)
                rebound.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_ui_exports_and_imports_local_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            token = "test-token"
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
            )
            host = f"127.0.0.1:{server.server_port}"
            server.RequestHandlerClass = make_handler(
                EstateStatusCache(manifest),
                token=token,
                allowed_hosts={host},
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                export_request = urllib.request.Request(
                    base + "/api/backup",
                    headers={"X-RAPP-Herdr-Token": token},
                )
                with urllib.request.urlopen(export_request, timeout=3) as response:
                    backup = json.loads(response.read())
                    self.assertEqual(
                        backup["schema"],
                        "rapp-herdr-estate-backup/1.0",
                    )
                    self.assertIn(
                        "attachment;",
                        response.headers["Content-Disposition"],
                    )

                backup["estate"]["name"] = "Restored Through UI"
                import_request = urllib.request.Request(
                    base + "/api/backup/import",
                    data=json.dumps(backup["estate"]).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-RAPP-Herdr-Token": token,
                    },
                )
                with urllib.request.urlopen(import_request, timeout=3) as response:
                    result = json.loads(response.read())
                    self.assertTrue(result["ok"])
                    self.assertTrue(Path(result["previous_manifest"]).is_file())
                self.assertEqual(
                    json.loads(manifest.read_text())["name"],
                    "Restored Through UI",
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_ui_refuses_lan_binding_without_explicit_opt_in(self) -> None:
        with self.assertRaisesRegex(RappHerdrError, "loopback"):
            run_ui("/missing", host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
