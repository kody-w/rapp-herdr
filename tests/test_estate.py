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
from rapp_herdr.probe import probe_rappid

from tests.helpers import write_json


def create_estate(path: Path) -> Path:
    write_json(
        path,
        {
            "schema": "rapp-herdr-estate/1.0",
            "name": "Test Estate",
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
                    "neighborhoods": [],
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
                    "neighborhoods": [
                        {
                            "manifest": "~/.rapp/neighborhoods/one/neighborhood.json",
                            "estate_roots": ["~/.rapp/twins"],
                            "base_port": 7081,
                        }
                    ],
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

    def test_device_payload_round_trips_without_shell_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            device = estate.devices[1]

            encoded = encode_device_payload(device)
            decoded = decode_device_payload(encoded)

            self.assertNotIn("~/.rapp", encoded)
            self.assertEqual(decoded, device.payload())

    def test_probe_observation_uses_the_receipt_allocated_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            manager = EstateManager(estate)
            device = estate.devices[0]
            runtime = {
                "ok": True,
                "reachable": True,
                "neighborhoods": [
                    {
                        "ok": True,
                        "result": {
                            "managed": True,
                            "state": "running",
                            "members": [
                                {
                                    "port": 7203,
                                    "rappid": probe_rappid(device.id),
                                    "managed": True,
                                    "live": True,
                                    "healthy": True,
                                }
                            ],
                        },
                    }
                ],
            }
            observed = {"ok": True, "device": device.id, "port": 7203}

            with patch.object(
                manager,
                "_run_local",
                return_value=runtime,
            ), patch.object(
                manager,
                "_run_local_probe",
                return_value=observed,
            ) as probe:
                result = manager._run_probe_observation(
                    device,
                    "verify",
                    base_port=7199,
                    message=None,
                )

            self.assertEqual(result, observed)
            self.assertEqual(probe.call_args.kwargs["base_port"], 7203)

    def test_probe_observation_rejects_diverged_runtime_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            manager = EstateManager(estate)
            device = estate.devices[0]
            runtime = {
                "ok": False,
                "reachable": True,
                "neighborhoods": [
                    {
                        "ok": False,
                        "result": {
                            "managed": False,
                            "state": "diverged",
                            "members": [{"port": 7203, "rappid": "wrong"}],
                        },
                    }
                ],
            }

            with patch.object(
                manager,
                "_run_local",
                return_value=runtime,
            ), patch.object(manager, "_run_local_probe") as probe:
                result = manager._run_probe_observation(
                    device,
                    "verify",
                    base_port=7199,
                    message=None,
                )

            self.assertFalse(result["ok"])
            self.assertIn("not running", result["error"])
            probe.assert_not_called()

    def test_probe_verification_cannot_pass_with_only_disabled_devices(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = create_estate(Path(directory) / "estate.json")
            value = json.loads(path.read_text())
            for device in value["devices"]:
                device["enabled"] = False
            write_json(path, value)
            manager = EstateManager(load_estate(path))

            result = manager.probe("verify")

            self.assertFalse(result["ok"])
            self.assertTrue(all(device["skipped"] for device in result["devices"]))

    def test_unsafe_ssh_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = create_estate(Path(directory) / "estate.json")
            value = json.loads(path.read_text())
            value["devices"][1]["ssh"] = "-oProxyCommand=bad"
            write_json(path, value)

            with self.assertRaisesRegex(RappHerdrError, "unsafe SSH alias"):
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

    @patch("rapp_herdr.estate.subprocess.run")
    def test_remote_probe_reads_structured_cli_error_from_stderr(self, run) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = load_estate(create_estate(Path(directory) / "estate.json"))
            device = estate.devices[1]
            run.return_value = subprocess.CompletedProcess(
                [],
                1,
                stdout="",
                stderr='{"ok":false,"error":"not restarted"}',
            )

            result = EstateManager(
                estate,
                ssh_binary="/usr/bin/ssh",
            )._run_remote_probe(
                device,
                "verify",
                base_port=7199,
                message=None,
            )

            self.assertFalse(result["ok"])
            self.assertTrue(result["reachable"])
            self.assertEqual(result["error"], "not restarted")

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
