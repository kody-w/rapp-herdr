from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.buddy import (
    BUDDY_SCHEMA,
    _ready_response,
    buddy_payload,
    create_buddy,
    decode_buddy_payload,
    encode_buddy_payload,
)


class BuddyTests(unittest.TestCase):
    def test_ready_requires_standalone_final_token(self) -> None:
        self.assertTrue(_ready_response("Research Buddy\nREADY"))
        self.assertFalse(_ready_response("Research Buddy UNREADY"))
        self.assertFalse(_ready_response("Research Buddy NOTREADY"))

    def _roots(self, root: Path) -> tuple[Path, Path, Path]:
        inventory = root / "twins"
        neighborhoods = root / "neighborhoods"
        brainstem = root / "brainstem"
        brainstem.mkdir()
        (brainstem / "brainstem.py").write_text("print('brainstem')\n")
        (brainstem / "index.html").write_text("<p>default chat</p>\n")
        return inventory, neighborhoods, brainstem

    def test_create_chat_buddy_mints_twin_and_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            with patch("rapp_herdr.buddy._select_port", return_value=7201):
                result = create_buddy(
                    buddy_payload(
                        "local-device",
                        str(inventory),
                        owner="test-owner",
                        name="Research Buddy",
                        role="Research questions and cite evidence.",
                        ui="chat",
                        neighborhood_root=str(neighborhoods),
                        brainstem_root=str(brainstem),
                    )
                )

            workspace = Path(result["workspace"])
            identity = json.loads((workspace / "rappid.json").read_text())
            application = json.loads(
                (workspace / "rapplication.json").read_text()
            )
            neighborhood = json.loads(
                Path(result["manifest"]).read_text()
            )
            self.assertEqual(identity["schema"], "rapp/1")
            self.assertEqual(identity["kind"], "twin")
            self.assertEqual(identity["ui"], "chat")
            self.assertTrue(identity["rappid"].startswith(
                "rappid:@test-owner/research-buddy:"
            ))
            self.assertEqual(
                application["ui"]["default_chat_fallback"],
                True,
            )
            self.assertEqual(neighborhood["schema"], "rapp-neighborhood/1.0")
            self.assertTrue((workspace / "agent.py").is_file())
            self.assertTrue(
                (workspace / "agents" / "buddy_role_agent.py").is_file()
            )
            self.assertFalse((workspace / "ui").exists())

    def test_auto_generates_custom_rapplication_ui_with_chat_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            with patch("rapp_herdr.buddy._select_port", return_value=7202):
                result = create_buddy(
                    buddy_payload(
                        "remote-device",
                        str(inventory),
                        owner="test-owner",
                        name="Portfolio Studio",
                        role="Build a visual portfolio dashboard and report workflow.",
                        ui="auto",
                        neighborhood_root=str(neighborhoods),
                        brainstem_root=str(brainstem),
                    )
                )

            workspace = Path(result["workspace"])
            page = (workspace / "ui" / "index.html").read_text()
            script = (workspace / "ui" / "ui.js").read_text()
            wrapper = (workspace / "brainstem.py").read_text()
            self.assertEqual(result["ui"], "rapplication")
            self.assertIn('href="/?ui=chat"', page)
            self.assertIn('data-rapp-action="default-chat"', page)
            self.assertIn("buddy_run", wrapper)
            self.assertIn('request.args.get("ui") == "chat"', wrapper)
            self.assertIn("session_id", script)
            self.assertIn("conversation_history", script)
            self.assertIn("history.slice(-40)", script)

    def test_buddy_payload_round_trips_without_plaintext(self) -> None:
        value = buddy_payload(
            "remote",
            "~/.rapp/twins",
            owner="test-owner",
            name="Private Buddy",
            role="Handle a role with shell-looking text; $(ignored).",
            ui="rapplication",
        )
        encoded = encode_buddy_payload(value)

        self.assertNotIn("Private Buddy", encoded)
        self.assertEqual(decode_buddy_payload(encoded), value)

    def test_create_refuses_unmanaged_existing_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            inventory.mkdir()
            # The minted suffix is random, so force the ownership check by
            # replacing mkdir with a deterministic collision.
            with patch("rapp_herdr.buddy._select_port", return_value=7203), patch(
                "rapp_herdr.buddy.uuid.uuid4"
            ) as mint:
                import uuid

                mint.return_value = uuid.UUID(
                    "12345678-1234-4234-8234-123456789abc"
                )
                payload = buddy_payload(
                    "local",
                    str(inventory),
                    owner="test-owner",
                    name="Collision",
                    role="Test collision handling.",
                    neighborhood_root=str(neighborhoods),
                    brainstem_root=str(brainstem),
                )
                first = create_buddy(payload)
                Path(first["workspace"], ".rapp-herdr-buddy.json").unlink()
                with self.assertRaisesRegex(Exception, "existing buddy path"):
                    create_buddy(payload)

    def test_custom_rapplication_serves_ui_and_default_chat_fallback(self) -> None:
        python = Path.home() / ".brainstem" / "venv" / "bin" / "python"
        if os.name == "nt":
            python = Path.home() / ".brainstem" / "venv" / "Scripts" / "python.exe"
        if not python.is_file():
            self.skipTest("Brainstem Flask environment is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            (brainstem / "brainstem.py").write_text(
                """import json, os
from flask import Flask, jsonify
app = Flask(__name__)
@app.get("/")
def index():
    return "DEFAULT CHAT"
@app.get("/health")
def health():
    return jsonify({"status": "ok"})
@app.post("/chat")
def chat():
    return jsonify({"response": "READY", "session_id": "test"})
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ["PORT"]), use_reloader=False)
"""
            )
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            with patch("rapp_herdr.buddy._select_port", return_value=port):
                result = create_buddy(
                    buddy_payload(
                        "local",
                        str(inventory),
                        owner="test-owner",
                        name="Visual Studio Buddy",
                        role="Build a visual dashboard.",
                        ui="rapplication",
                        neighborhood_root=str(neighborhoods),
                        brainstem_root=str(brainstem),
                    )
                )
            process = subprocess.Popen(
                [str(python), "brainstem.py"],
                cwd=result["workspace"],
                env={**os.environ, "PORT": str(port)},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/health",
                            timeout=1,
                        ):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    self.fail("custom rapplication did not start")
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/",
                    timeout=3,
                ) as response:
                    custom = response.read().decode()
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/?ui=chat",
                    timeout=3,
                ) as response:
                    fallback = response.read().decode()
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/buddy.css",
                    timeout=3,
                ) as response:
                    css = response.read().decode()

                self.assertIn("Visual Studio Buddy", custom)
                self.assertIn("Use default chat", custom)
                self.assertIn("default chat", fallback)
                self.assertIn("var(--cp-accent)", css)
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/buddy-identity",
                    timeout=3,
                ) as response:
                    identity = json.loads(response.read())
                self.assertEqual(identity["rappid"], result["rappid"])
                self.assertEqual(
                    identity["identity_nonce"],
                    result["identity_nonce"],
                )
            finally:
                process.terminate()
                process.wait(timeout=10)

    def test_adversarial_name_cannot_escape_generated_python_or_html(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            name = 'x"""; raise RuntimeError("INJECTED"); <script>'
            with patch("rapp_herdr.buddy._select_port", return_value=7205):
                result = create_buddy(
                    buddy_payload(
                        "local",
                        str(inventory),
                        owner="test-owner",
                        name=name,
                        role="Build a visual dashboard.",
                        ui="rapplication",
                        neighborhood_root=str(neighborhoods),
                        brainstem_root=str(brainstem),
                    )
                )
            workspace = Path(result["workspace"])
            source = (workspace / "agent.py").read_text()
            page = (workspace / "ui" / "index.html").read_text()

            compile(source, str(workspace / "agent.py"), "exec")
            namespace = {}
            exec(source, namespace)
            self.assertIn("BuddyRoleAgent", namespace)
            self.assertNotIn(
                'name = \'x"""; raise RuntimeError("INJECTED"); <script>\'',
                source,
            )
            self.assertIn("raise RuntimeError", page)
            self.assertNotIn("<script><script>", page)

    def test_name_rejects_controls_before_creating_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)

            with self.assertRaisesRegex(
                Exception,
                "unsafe control character",
            ):
                create_buddy(
                    buddy_payload(
                        "local",
                        str(inventory),
                        owner="test-owner",
                        name="Persistence\nProbe",
                        role="Chat.",
                        neighborhood_root=str(neighborhoods),
                        brainstem_root=str(brainstem),
                    )
                )

            self.assertFalse(inventory.exists())
            self.assertFalse(neighborhoods.exists())

    def test_owner_must_be_canonical_and_independent_from_device(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            with self.assertRaisesRegex(Exception, "canonical RAPP/1 owner"):
                create_buddy(
                    buddy_payload(
                        "device-name",
                        str(inventory),
                        owner="INVALID_OWNER",
                        name="Buddy",
                        role="Chat.",
                        neighborhood_root=str(neighborhoods),
                        brainstem_root=str(brainstem),
                    )
                )

    def test_failed_generation_removes_staging_and_partial_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, neighborhoods, brainstem = self._roots(root)
            from rapp_herdr import buddy

            original = buddy._write_json
            calls = 0

            def fail_after_marker(path, value):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("injected write failure")
                return original(path, value)

            with patch("rapp_herdr.buddy._select_port", return_value=7206), patch(
                "rapp_herdr.buddy._write_json",
                side_effect=fail_after_marker,
            ):
                with self.assertRaisesRegex(OSError, "injected write failure"):
                    create_buddy(
                        buddy_payload(
                            "local",
                            str(inventory),
                            owner="test-owner",
                            name="Transactional Buddy",
                            role="Test atomic creation.",
                            neighborhood_root=str(neighborhoods),
                            brainstem_root=str(brainstem),
                        )
                    )

            self.assertEqual(list(inventory.iterdir()), [])
            self.assertEqual(list(neighborhoods.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
