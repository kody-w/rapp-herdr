from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.estate import (
    EstateManager,
    _neighborhood_ownership_ok,
    _windows_herdr_task_command,
    decode_device_payload,
    encode_device_payload,
    load_estate,
    run_estate_device,
)
from rapp_herdr.model import RappHerdrError

from tests.helpers import write_json


def create_estate(path: Path) -> Path:
    write_json(
        path,
        {
            "schema": "rapp-herdr-estate/1.0",
            "name": "Test Estate",
            "buddy_owner": "test-owner",
            "devices": [
                {
                    "id": "local",
                    "transport": "local",
                    "os": "posix",
                    "session": "rapp-estate",
                    "herdr_bin": "/opt/herdr",
                    "rapp_herdr_bin": "/opt/rapp-herdr",
                    "receipt_root": None,
                    "inventory_roots": ["~/.rapp/twins"],
                    "catalog_roots": [],
                    "audit_roots": [],
                    "neighborhoods": [],
                    "probe_target": {
                        "name": "Local Twin",
                        "url": "http://127.0.0.1:7085",
                        "rappid": "rappid:@test/local:" + "a" * 64,
                    },
                },
                {
                    "id": "remote-mac",
                    "transport": "ssh",
                    "ssh": "remote-mac",
                    "os": "posix",
                    "session": "rapp-estate",
                    "herdr_bin": "/Users/remote/.local/bin/herdr",
                    "rapp_herdr_bin": "/Users/remote/.local/bin/rapp-herdr",
                    "receipt_root": None,
                    "inventory_roots": ["~/.rapp/twins"],
                    "catalog_roots": [],
                    "audit_roots": [],
                    "neighborhoods": [
                        {
                            "manifest": "~/.rapp/neighborhoods/one/neighborhood.json",
                            "estate_roots": ["~/.rapp/twins"],
                            "base_port": 7081,
                        }
                    ],
                    "probe_target": {
                        "name": "Remote Twin",
                        "url": "http://127.0.0.1:7081",
                        "rappid": "rappid:@test/remote:" + "b" * 64,
                    },
                },
            ],
        },
    )
    return path


class EstateTests(unittest.TestCase):
    def test_windows_herdr_task_command_hides_paths_from_shell_text(self) -> None:
        command = _windows_herdr_task_command(
            r"C:\Program Files\Herdr\herdr.exe",
            "rapp-estate",
        )

        self.assertEqual(command[0], "powershell.exe")
        self.assertNotIn("Program Files", " ".join(command))
        self.assertNotIn("rapp-estate", " ".join(command))

    def test_diverged_neighborhood_fails_estate_ownership(self) -> None:
        self.assertFalse(
            _neighborhood_ownership_ok(
                {"state": "diverged", "managed": False}
            )
        )
        self.assertTrue(
            _neighborhood_ownership_ok(
                {"state": "degraded", "managed": True}
            )
        )
        self.assertTrue(
            _neighborhood_ownership_ok(
                {"state": "down", "managed": False}
            )
        )

    @patch("rapp_herdr.estate.audit_machine", side_effect=RappHerdrError("audit broke"))
    @patch("rapp_herdr.estate._start_herdr_session")
    def test_explicit_audit_fails_without_invalidating_lifecycle_actions(
        self, start, _audit
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            start.return_value = object()
            payload = {
                "id": "local",
                "session": "rapp-estate",
                "herdr_bin": "/opt/herdr",
                "inventory_roots": [directory],
                "catalog_roots": [],
                "audit_roots": [],
                "neighborhoods": [],
            }

            audit = run_estate_device("audit", payload)
            up = run_estate_device("up", payload)

            self.assertFalse(audit["ok"])
            self.assertFalse(audit["audit"]["ok"])
            self.assertTrue(up["ok"])
            self.assertFalse(up["audit"]["ok"])

    def test_estate_plan_preserves_device_and_neighborhood_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))

            plan = EstateManager(estate, ssh_binary="/usr/bin/ssh").plan()

            self.assertTrue(plan["ok"])
            self.assertEqual([device["id"] for device in plan["devices"]], [
                "local",
                "remote-mac",
            ])
            self.assertEqual(
                plan["devices"][1]["neighborhoods"][0]["base_port"],
                7081,
            )
            self.assertEqual(
                plan["devices"][1]["probe_target"]["name"],
                "Remote Twin",
            )

    def test_device_payload_round_trips_without_shell_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            device = estate.devices[1]

            encoded = encode_device_payload(device)
            decoded = decode_device_payload(encoded)

            self.assertNotIn("~/.rapp", encoded)
            self.assertEqual(decoded, device.payload())

    def test_create_buddy_registers_starts_and_handshakes_online(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = create_estate(root / "estate.json")
            estate = load_estate(path)
            buddy_manifest = root / "buddy" / "neighborhood.json"
            created = {
                "ok": True,
                "name": "Research Buddy",
                "rappid": "rappid:@local/research:" + "c" * 64,
                "port": 7200,
                "identity_nonce": "test-identity-nonce",
                "neighborhood": {
                    "manifest": str(buddy_manifest),
                    "estate_roots": [str(root / "twins")],
                    "base_port": 7200,
                    "brainstem_python": "~/.brainstem/venv/bin/python",
                    "bootstrap": False,
                    "listen_host": "127.0.0.1",
                    "entrypoint": "brainstem.py",
                },
            }

            def buddy_runner(_device, action, _payload):
                if action == "create":
                    return created
                return {
                    "ok": True,
                    "ready": True,
                    "response": "Research Buddy READY",
                }

            with patch.object(
                EstateManager,
                "_run_local_buddy",
                side_effect=buddy_runner,
            ), patch.object(
                EstateManager,
                "_run_local",
                return_value={
                    "ok": True,
                    "device": "local",
                    "neighborhoods": [{
                        "result": {
                            "members": [{
                                "rappid": created["rappid"],
                                "port": 7201,
                                "healthy": True,
                            }]
                        }
                    }],
                },
            ):
                result = EstateManager(estate).create_buddy(
                    device_id="local",
                    name="Research Buddy",
                    role="Research and cite evidence.",
                    ui="chat",
                )

            self.assertTrue(result["ok"])
            self.assertEqual(result["presence"], "online")
            self.assertEqual(result["actual_port"], 7201)
            updated = json.loads(path.read_text())
            registered = updated["devices"][0]["neighborhoods"][-1]
            self.assertEqual(registered["managed_by"], "rapp-herdr-buddy/1.0")
            self.assertEqual(registered["base_port"], 7200)

    def test_failed_buddy_handshake_rolls_back_only_created_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = create_estate(root / "estate.json")
            original = json.loads(path.read_text())
            estate = load_estate(path)
            created = {
                "ok": True,
                "name": "Failed Buddy",
                "rappid": "rappid:@test-owner/failed:" + "d" * 64,
                "workspace": str(root / "twins" / "failed"),
                "manifest": str(root / "buddy" / "neighborhood.json"),
                "port": 7200,
                "identity_nonce": "failed-buddy-nonce",
                "neighborhood": {
                    "manifest": str(root / "buddy" / "neighborhood.json"),
                    "estate_roots": [str(root / "twins")],
                    "base_port": 7200,
                    "brainstem_python": "~/.brainstem/venv/bin/python",
                    "bootstrap": False,
                    "listen_host": "127.0.0.1",
                    "entrypoint": "brainstem.py",
                },
            }
            buddy_actions = []

            def buddy_runner(_device, action, _payload):
                buddy_actions.append(action)
                if action == "create":
                    return created
                if action == "delete":
                    return {"ok": True, "deleted": True}
                return {"ok": False, "ready": False, "error": "no READY"}

            def lifecycle_runner(_device, action):
                if action == "down":
                    return {"ok": True, "state": "down"}
                return {
                    "ok": True,
                    "neighborhoods": [{
                        "result": {
                            "members": [{
                                "rappid": created["rappid"],
                                "port": 7204,
                            }]
                        }
                    }],
                }

            with patch.object(
                EstateManager,
                "_run_local_buddy",
                side_effect=buddy_runner,
            ), patch.object(
                EstateManager,
                "_run_local",
                side_effect=lifecycle_runner,
            ):
                result = EstateManager(estate).create_buddy(
                    device_id="local",
                    name="Failed Buddy",
                    role="Fail the handshake.",
                    ui="chat",
                )

            self.assertFalse(result["ok"])
            self.assertTrue(result["rollback"]["ok"])
            self.assertEqual(result["presence"], "offline")
            self.assertEqual(buddy_actions, ["create", "handshake", "delete"])
            self.assertEqual(json.loads(path.read_text()), original)

    def test_unsafe_ssh_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = create_estate(Path(directory) / "estate.json")
            value = json.loads(path.read_text())
            value["devices"][1]["ssh"] = "-oProxyCommand=bad"
            write_json(path, value)

            with self.assertRaisesRegex(RappHerdrError, "unsafe SSH alias"):
                load_estate(path)

    def test_root_fields_require_arrays_and_inventory_is_nonempty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = create_estate(Path(directory) / "estate.json")
            value = json.loads(path.read_text())
            value["devices"][0]["audit_roots"] = "/"
            write_json(path, value)
            with self.assertRaisesRegex(RappHerdrError, "audit_roots must be an array"):
                load_estate(path)

            value["devices"][0]["audit_roots"] = []
            value["devices"][0]["inventory_roots"] = []
            write_json(path, value)
            with self.assertRaisesRegex(RappHerdrError, "at least one path"):
                load_estate(path)

    @patch("rapp_herdr.estate.subprocess.run")
    def test_remote_invocation_contains_only_encoded_payload(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            run.return_value = subprocess.CompletedProcess(
                [],
                0,
                stdout='{"ok":true,"device":"remote-mac"}',
                stderr="",
            )
            manager = EstateManager(estate, ssh_binary="/usr/bin/ssh")

            result = manager._run_remote(estate.devices[1], "status")

            self.assertTrue(result["ok"])
            command = run.call_args.args[0]
            self.assertEqual(command[0], "/usr/bin/ssh")
            self.assertNotIn("~/.rapp", command[-1])
            self.assertIn("_estate-device", command[-1])

    @patch(
        "rapp_herdr.estate.subprocess.run",
        side_effect=subprocess.TimeoutExpired(["ssh"], 240),
    )
    def test_remote_buddy_timeout_is_structured_and_indeterminate(
        self,
        _run,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            device = estate.devices[1]

            result = EstateManager(
                estate,
                ssh_binary="/usr/bin/ssh",
            )._run_remote_buddy(
                device,
                "create",
                {"schema": "rapp-herdr-buddy/1.0"},
            )

            self.assertFalse(result["ok"])
            self.assertTrue(result["reachable"])
            self.assertTrue(result["indeterminate"])

    @patch("rapp_herdr.estate.subprocess.run")
    def test_remote_structured_failure_remains_reachable(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            run.return_value = subprocess.CompletedProcess(
                [],
                1,
                stdout='{"ok":false,"device":"remote-mac","error":"diverged"}',
                stderr="",
            )

            result = EstateManager(
                estate,
                ssh_binary="/usr/bin/ssh",
            )._run_remote(estate.devices[1], "status")

            self.assertFalse(result["ok"])
            self.assertTrue(result["reachable"])
            self.assertEqual(result["error"], "diverged")

    @patch("rapp_herdr.estate._start_herdr_session")
    def test_device_with_no_neighborhoods_still_starts_session(self, start) -> None:
        with tempfile.TemporaryDirectory() as directory:
            start.return_value = object()
            payload = {
                "id": "empty-device",
                "session": "rapp-estate",
                "herdr_bin": "/opt/herdr",
                "inventory_roots": [directory],
                "neighborhoods": [],
            }

            result = run_estate_device("up", payload)

            self.assertTrue(result["ok"])
            self.assertEqual(result["session"], "running")
            self.assertEqual(result["neighborhoods"], [])
            self.assertEqual(result["inventory"]["total"], 0)
            start.assert_called_once_with(
                str(Path("/opt/herdr").expanduser()),
                "rapp-estate",
            )


if __name__ == "__main__":
    unittest.main()
