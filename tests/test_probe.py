from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.bootstrap import _is_persistence_probe
from rapp_herdr.model import RappHerdrError
from rapp_herdr.probe import (
    PROBE_NEIGHBORHOOD_NAME,
    PROBE_SCHEMA,
    add_probe_neighborhoods,
    probe_payload,
    probe_rappid,
    run_probe_device,
)
from tests.test_estate import create_estate


class PersistenceProbeTests(unittest.TestCase):
    def test_only_managed_probe_marker_enables_lightweight_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = (
                Path(directory)
                / "rapp-herdr-persistence-probe-device-one"
            )
            workspace.mkdir()
            rappid = probe_rappid("device-one")
            arguments = {
                "rappid": rappid,
                "neighborhood": PROBE_NEIGHBORHOOD_NAME,
                "entrypoint": "brainstem.py",
            }
            self.assertFalse(_is_persistence_probe(workspace, **arguments))
            (workspace / ".rapp-herdr-probe.json").write_text(
                json.dumps(
                    {
                        "schema": PROBE_SCHEMA,
                        "device_id": "device-one",
                        "rappid": rappid,
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(_is_persistence_probe(workspace, **arguments))
            self.assertFalse(
                _is_persistence_probe(
                    workspace,
                    **{**arguments, "rappid": probe_rappid("other-device")},
                )
            )

    def test_seed_is_isolated_idempotent_and_preserves_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )

            first = run_probe_device("seed", payload)
            state_path = (
                Path(first["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            state = json.loads(state_path.read_text())
            state["message_count"] = 7
            state_path.write_text(json.dumps(state))

            second = run_probe_device("seed", payload)

            self.assertTrue(second["ok"])
            self.assertEqual(
                json.loads(state_path.read_text())["message_count"],
                7,
            )
            self.assertTrue((Path(first["workspace"]) / "brainstem.py").is_file())
            self.assertFalse(
                (Path(first["workspace"]) / "requirements.txt").exists()
            )
            compile(
                (Path(first["workspace"]) / "brainstem.py").read_text(),
                "brainstem.py",
                "exec",
            )

    def test_seed_refuses_an_unmanaged_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = (
                root / "twins" / "rapp-herdr-persistence-probe-device-one"
            )
            workspace.mkdir(parents=True)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )

            with self.assertRaisesRegex(RappHerdrError, "unmanaged"):
                run_probe_device("seed", payload)

    def test_mark_and_verify_require_matching_persistent_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                message="survive this",
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            state_path = (
                Path(seeded["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            marked_state = {
                **seeded["state"],
                "boot_count": 1,
                "message_count": 1,
                "messages": [{"content": "survive this"}],
            }
            state_path.write_text(json.dumps(marked_state), encoding="utf-8")

            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": marked_state},
            ):
                marked = run_probe_device("mark", payload)
                with self.assertRaisesRegex(RappHerdrError, "not restarted"):
                    run_probe_device("verify", payload)

            restarted_state = {**marked_state, "boot_count": 2}
            state_path.write_text(json.dumps(restarted_state), encoding="utf-8")
            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": restarted_state},
            ):
                verified = run_probe_device("verify", payload)

            self.assertEqual(
                marked["state"]["survival_marker"],
                verified["state"]["survival_marker"],
            )
            self.assertEqual(verified["state"]["message_count"], 1)

    def test_seed_refuses_an_unmanaged_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            neighborhood = root / "neighborhood"
            neighborhood.mkdir()
            (neighborhood / "neighborhood.json").write_text(
                json.dumps({"schema": "someone-elses-neighborhood/1.0"}),
                encoding="utf-8",
            )
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    neighborhood / "neighborhood.json"
                ),
            )

            with self.assertRaisesRegex(RappHerdrError, "unmanaged"):
                run_probe_device("seed", payload)

    def test_estate_manifest_adds_only_managed_probe_neighborhoods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")

            result = add_probe_neighborhoods(
                manifest,
                {"local", "remote-mac"},
                base_port=7199,
            )

            self.assertTrue(result["changed"])
            updated = json.loads(manifest.read_text())
            for device in updated["devices"]:
                probe = device["neighborhoods"][-1]
                self.assertEqual(probe["managed_by"], PROBE_SCHEMA)
                self.assertEqual(probe["base_port"], 7199)
                self.assertIn(".brainstem/venv", probe["brainstem_python"])
                self.assertFalse(probe["bootstrap"])
            self.assertTrue(Path(result["previous_manifest"]).is_file())


if __name__ == "__main__":
    unittest.main()
