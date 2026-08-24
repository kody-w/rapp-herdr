from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rapp_herdr.probe import (
    PROBE_SCHEMA,
    add_probe_neighborhoods,
    probe_payload,
    probe_rappid,
    run_probe_device,
)

from tests.helpers import write_json


class ProbeTests(unittest.TestCase):
    RELAY_TARGET = {
        "name": "Local Twin",
        "url": "http://127.0.0.1:7081",
        "rappid": "rappid:@test/local-twin:" + "a" * 64,
    }

    def test_seed_creates_owned_bounded_probe_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "local",
                str(root / "twins"),
                base_port=7199,
                relay_target=self.RELAY_TARGET,
                neighborhood_manifest=str(root / "neighborhood" / "neighborhood.json"),
            )

            result = run_probe_device("seed", payload)

            workspace = Path(result["workspace"])
            identity = json.loads((workspace / "rappid.json").read_text())
            self.assertEqual(identity["schema"], "rapp/1")
            self.assertEqual(identity["rappid"], probe_rappid("local"))
            self.assertTrue((workspace / ".rapp-herdr-probe.json").is_file())
            self.assertTrue((workspace / "brainstem.py").is_file())
            self.assertEqual(result["state"]["schema"], PROBE_SCHEMA)
            self.assertEqual(
                result["state"]["relay_target"],
                self.RELAY_TARGET,
            )
            source = (workspace / "brainstem.py").read_text()
            self.assertIn("relay_turn", source)
            self.assertNotIn("Persistence marker stored locally.", source)

    def test_seed_adds_probe_neighborhood_with_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "estate.json"
            write_json(
                manifest,
                {
                    "schema": "rapp-herdr-estate/1.0",
                    "name": "Probe Estate",
                    "devices": [
                        {
                            "id": "local",
                            "transport": "local",
                            "os": "posix",
                            "session": "rapp-estate",
                            "herdr_bin": "/opt/herdr",
                            "rapp_herdr_bin": "/opt/rapp-herdr",
                            "inventory_roots": [str(root / "twins")],
                            "catalog_roots": [],
                            "audit_roots": [],
                            "neighborhoods": [],
                        }
                    ],
                },
            )

            result = add_probe_neighborhoods(
                manifest,
                {"local"},
                base_port=7199,
            )

            self.assertTrue(result["changed"])
            value = json.loads(manifest.read_text())
            neighborhood = value["devices"][0]["neighborhoods"][0]
            self.assertEqual(neighborhood["managed_by"], PROBE_SCHEMA)
            self.assertTrue(Path(result["previous_manifest"]).is_file())

    def test_seed_refuses_unmanaged_probe_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "neighborhood" / "neighborhood.json"
            write_json(
                manifest,
                {
                    "schema": "rapp-neighborhood/1.0",
                    "name": "user-owned",
                    "neighborhood_rappid": "rappid:@user/owned:" + "a" * 64,
                },
            )
            payload = probe_payload(
                "local",
                str(root / "twins"),
                base_port=7199,
                relay_target=self.RELAY_TARGET,
                neighborhood_manifest=str(manifest),
            )

            with self.assertRaisesRegex(Exception, "unmanaged probe neighborhood"):
                run_probe_device("seed", payload)

            self.assertEqual(
                json.loads(manifest.read_text())["name"],
                "user-owned",
            )

    def test_seed_requires_a_different_loopback_twin_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "local",
                str(root / "twins"),
                base_port=7199,
                relay_target={
                    "name": "Recursive Probe",
                    "url": "http://127.0.0.1:7199",
                },
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )

            with self.assertRaisesRegex(Exception, "different loopback HTTP port"):
                run_probe_device("seed", payload)

    def test_generated_probe_relays_chat_to_real_local_twin(self) -> None:
        python = Path.home() / ".brainstem" / "venv" / "bin" / "python"
        if os.name == "nt":
            python = Path.home() / ".brainstem" / "venv" / "Scripts" / "python.exe"
        if not python.is_file():
            self.skipTest("Brainstem Flask environment is unavailable")

        class TwinHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def do_GET(self) -> None:
                value = json.dumps({"status": "ok"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(value)))
                self.end_headers()
                self.wfile.write(value)

            def do_POST(self) -> None:
                size = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(size))
                if body["user_input"] == "slow relay":
                    time.sleep(5.5)
                if body["user_input"] == "fail relay":
                    value = json.dumps({"error": "injected failure"}).encode()
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(value)))
                    self.end_headers()
                    self.wfile.write(value)
                    return
                value = json.dumps(
                    {
                        "response": "REAL TWIN READY: " + body["user_input"],
                        "session_id": "real-twin-session",
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(value)))
                self.end_headers()
                self.wfile.write(value)

        target = ThreadingHTTPServer(("127.0.0.1", 0), TwinHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            probe_port = reservation.getsockname()[1]
        process = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                relay_target = {
                    "name": "Real Local Twin",
                    "url": f"http://127.0.0.1:{target.server_port}",
                    "rappid": "rappid:@test/real-local:" + "b" * 64,
                }
                payload = probe_payload(
                    "local",
                    str(root / "twins"),
                    base_port=probe_port,
                    relay_target=relay_target,
                    neighborhood_manifest=str(
                        root / "neighborhood" / "neighborhood.json"
                    ),
                )
                seeded = run_probe_device("seed", payload)
                process = subprocess.Popen(
                    [str(python), "brainstem.py"],
                    cwd=seeded["workspace"],
                    env={**os.environ, "PORT": str(probe_port)},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{probe_port}/health",
                            timeout=1,
                        ):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    self.fail("generated persistence probe did not start")
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{probe_port}/health",
                    timeout=2,
                ) as response:
                    initial_health = json.loads(response.read())
                self.assertTrue(initial_health["target_healthy"])
                self.assertFalse(initial_health["target_ready"])
                request = urllib.request.Request(
                    f"http://127.0.0.1:{probe_port}/chat",
                    data=json.dumps({"user_input": "relay this"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    value = json.loads(response.read())

                self.assertEqual(
                    value["response"],
                    "REAL TWIN READY: relay this",
                )
                self.assertTrue(value["relay"]["responded"])
                self.assertEqual(
                    value["relay"]["target_name"],
                    "Real Local Twin",
                )
                self.assertEqual(value["probe"]["relay_count"], 1)
                self.assertEqual(
                    value["relay"]["target_revision"],
                    value["probe"]["target_revision"],
                )
                state_path = (
                    Path(seeded["workspace"])
                    / ".brainstem_data"
                    / "persistence_probe.json"
                )
                state = json.loads(state_path.read_text())
                state["messages"] = [
                    {"content": "x" * 8_000, "recorded_at": "test"}
                    for _ in range(100)
                ]
                state_path.write_text(json.dumps(state))
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{probe_port}/health",
                    timeout=2,
                ) as response:
                    health_body = response.read()
                health = json.loads(health_body)
                self.assertLess(len(health_body), 64 * 1024)
                self.assertNotIn("messages", health["probe"])
                self.assertTrue(health["target_ready"])

                slow_payload = dict(payload, message="slow relay")
                slow = run_probe_device("mark", slow_payload)
                self.assertTrue(slow["ok"])
                self.assertTrue(slow["relay"]["responded"])

                failed_payload = dict(payload, message="fail relay")
                failed = run_probe_device("mark", failed_payload)
                self.assertFalse(failed["ok"])
                self.assertTrue(failed["reachable"])
                self.assertFalse(failed["relay"]["responded"])
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{probe_port}/health",
                    timeout=2,
                ) as response:
                    failed_health = json.loads(response.read())
                self.assertFalse(failed_health["target_ready"])
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_reseed_clears_session_when_target_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = str(root / "neighborhood" / "neighborhood.json")
            first_target = dict(
                self.RELAY_TARGET,
                url="http://127.0.0.1:7081",
            )
            payload = probe_payload(
                "local",
                str(root / "twins"),
                base_port=7199,
                relay_target=first_target,
                neighborhood_manifest=manifest,
            )
            seeded = run_probe_device("seed", payload)
            state_path = (
                Path(seeded["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            state = json.loads(state_path.read_text())
            state["target_session_id"] = "old-target-session"
            state_path.write_text(json.dumps(state))

            second_target = dict(
                self.RELAY_TARGET,
                name="Replacement Twin",
                url="http://127.0.0.1:7082",
            )
            run_probe_device(
                "seed",
                dict(payload, relay_target=second_target),
            )
            updated = json.loads(state_path.read_text())

            self.assertEqual(updated["relay_target"], second_target)
            self.assertNotIn("target_session_id", updated)


if __name__ == "__main__":
    unittest.main()
