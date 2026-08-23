from __future__ import annotations

import json
import tempfile
import unittest
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
    def test_seed_creates_owned_bounded_probe_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "local",
                str(root / "twins"),
                base_port=7199,
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
                neighborhood_manifest=str(manifest),
            )

            with self.assertRaisesRegex(Exception, "unmanaged probe neighborhood"):
                run_probe_device("seed", payload)

            self.assertEqual(
                json.loads(manifest.read_text())["name"],
                "user-owned",
            )


if __name__ == "__main__":
    unittest.main()
