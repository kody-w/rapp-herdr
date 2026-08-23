from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from rapp_herdr.backup import BACKUP_SCHEMA, MAX_BACKUP_BYTES
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
        self.assertIn(
            'data-max-backup-bytes="__RAPP_HERDR_MAX_BACKUP_BYTES__"',
            html,
        )
        self.assertIn('await fetch("/api/backup"', html)
        self.assertIn("if (!response.ok)", html)
        self.assertIn("await response.blob()", html)
        self.assertIn("Backup download started", html)
        self.assertNotIn("Backup exported", html)

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
                html = response.read()
                self.assertIn(b"RAPP-Herdr Estate", html)
                self.assertIn(
                    f'data-max-backup-bytes="{MAX_BACKUP_BYTES}"'.encode(),
                    html,
                )
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
                    serialized_backup = response.read()
                    backup = json.loads(serialized_backup)
                    self.assertLessEqual(
                        len(serialized_backup),
                        MAX_BACKUP_BYTES,
                    )
                    self.assertEqual(
                        backup["schema"],
                        BACKUP_SCHEMA,
                    )
                    self.assertIn(
                        "attachment;",
                        response.headers["Content-Disposition"],
                    )

                changed = json.loads(manifest.read_text(encoding="utf-8"))
                changed["name"] = "Changed Before UI Restore"
                manifest.write_text(
                    json.dumps(changed, indent=2) + "\n",
                    encoding="utf-8",
                )
                predecessor = manifest.read_bytes()
                import_request = urllib.request.Request(
                    base + "/api/backup/import",
                    data=serialized_backup,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-RAPP-Herdr-Token": token,
                    },
                )
                with urllib.request.urlopen(import_request, timeout=3) as response:
                    result = json.loads(response.read())
                    self.assertTrue(result["ok"])
                    self.assertEqual(result["source_schema"], BACKUP_SCHEMA)
                    self.assertTrue(Path(result["previous_manifest"]).is_file())
                    self.assertEqual(
                        Path(result["previous_manifest"]).read_bytes(),
                        predecessor,
                    )
                self.assertEqual(
                    json.loads(manifest.read_text())["name"],
                    "Test Estate",
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_ui_rejects_mutated_checksummed_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
            token = "test-token"
            cache = EstateStatusCache(manifest)
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
            )
            host = f"127.0.0.1:{server.server_port}"
            server.RequestHandlerClass = make_handler(
                cache,
                token=token,
                allowed_hosts={host},
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                request = urllib.request.Request(
                    base + "/api/backup",
                    headers={"X-RAPP-Herdr-Token": token},
                )
                with urllib.request.urlopen(request, timeout=3) as response:
                    envelope = json.loads(response.read())
                envelope["estate"]["name"] = "Checksum Mutation"
                request = urllib.request.Request(
                    base + "/api/backup/import",
                    data=json.dumps(envelope).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-RAPP-Herdr-Token": token,
                    },
                )

                with self.assertRaises(HTTPError) as failure:
                    urllib.request.urlopen(request, timeout=3)

                self.assertEqual(failure.exception.code, 400)
                self.assertIn(b"checksum", failure.exception.read())
                failure.exception.close()
                self.assertEqual(manifest.read_bytes(), before)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_ui_refuses_export_larger_than_restore_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            oversized = json.loads(manifest.read_text(encoding="utf-8"))
            oversized["padding"] = "x" * MAX_BACKUP_BYTES
            manifest.write_text(
                json.dumps(oversized, indent=2) + "\n",
                encoding="utf-8",
            )
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
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/backup",
                    headers={"X-RAPP-Herdr-Token": token},
                )

                with self.assertRaises(HTTPError) as failure:
                    urllib.request.urlopen(request, timeout=3)

                self.assertEqual(failure.exception.code, 413)
                self.assertRegex(
                    failure.exception.read().decode("utf-8"),
                    r"(backup|restore) limit",
                )
                failure.exception.close()
                failure.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_ui_refuses_import_body_larger_than_restore_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
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
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                server.server_port,
                timeout=3,
            )
            try:
                connection.putrequest(
                    "POST",
                    "/api/backup/import",
                    skip_host=True,
                )
                connection.putheader("Host", host)
                connection.putheader("Content-Type", "application/json")
                connection.putheader("X-RAPP-Herdr-Token", token)
                connection.putheader(
                    "Content-Length",
                    str(MAX_BACKUP_BYTES + 1),
                )
                connection.endheaders()

                failure = connection.getresponse()
                self.assertEqual(failure.status, 413)
                self.assertIn(
                    str(MAX_BACKUP_BYTES).encode(),
                    failure.read(),
                )
                self.assertEqual(manifest.read_bytes(), before)
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_cache_is_invalidated_even_when_import_raises(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            cache = EstateStatusCache(manifest)
            cache._value = {"estate": "stale"}
            cache._expires_at = float("inf")

            with (
                patch(
                    "rapp_herdr.ui.import_estate_backup",
                    side_effect=RappHerdrError("injected failure"),
                ),
                self.assertRaisesRegex(RappHerdrError, "injected failure"),
            ):
                cache.import_backup({})

            self.assertIsNone(cache._value)
            self.assertEqual(cache._expires_at, 0.0)

    def test_ui_refuses_lan_binding_without_explicit_opt_in(self) -> None:
        with self.assertRaisesRegex(RappHerdrError, "loopback"):
            run_ui("/missing", host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
