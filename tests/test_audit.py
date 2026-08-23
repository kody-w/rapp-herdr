from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.audit import _classification, audit_machine

from tests.helpers import write_json


class AuditTests(unittest.TestCase):
    def test_compliance_classification_is_explicitly_unverified(self) -> None:
        path = Path("/tmp/rappid.json")

        self.assertEqual(
            _classification(path, {"schema": "rapp/1"}),
            "declared-rapp1-unverified",
        )
        self.assertEqual(
            _classification(path, {"schema": "rapp-rappid/2.0"}),
            "legacy-rapp",
        )
        self.assertEqual(
            _classification(Path("/tmp/project/manifest.json"), {"name": "AI"}),
            "non-rapp-ai",
        )

    @patch("rapp_herdr.audit._unix_listeners", return_value=[])
    @patch("rapp_herdr.audit._unix_jobs", return_value=[])
    @patch(
        "rapp_herdr.audit._herdr_snapshot",
        return_value={
            "sessions": [],
            "workspace_count": 0,
            "pane_count": 0,
            "agent_count": 0,
            "agent_kinds": [],
        },
    )
    def test_machine_audit_separates_assets_and_administrative_metadata(
        self, _herdr, _jobs, _listeners
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            twin = home / ".rapp" / "twins" / "one"
            write_json(
                twin / "rappid.json",
                {
                    "schema": "rapp/1",
                    "rappid": "rappid:@test/one:" + "a" * 64,
                    "kind": "twin",
                    "name": "One",
                },
            )
            (twin / "brainstem.py").write_text("", encoding="utf-8")
            (home / ".rapp" / "twins" / ".receipts").mkdir()
            legacy = home / ".brainstem" / "twins" / "legacy"
            write_json(
                legacy / "rappid.json",
                {
                    "schema": "rapp-rappid/2.0",
                    "rappid": "legacy",
                    "name": "Legacy",
                },
            )
            with patch("rapp_herdr.audit.Path.home", return_value=home):
                result = audit_machine(
                    {
                        "herdr_bin": "/missing/herdr",
                        "session": "rapp-estate",
                        "audit_roots": [],
                    },
                    assigned_rappids={"rappid:@test/one:" + "a" * 64},
                )

            self.assertEqual(result["schema"], "rapp-herdr-audit/1.0")
            compliance = result["compliance_counts"]
            self.assertEqual(compliance["declared-rapp1-unverified"], 1)
            self.assertEqual(compliance["legacy-rapp"], 1)
            self.assertTrue(
                any(
                    asset["type"] == "administrative-metadata"
                    for asset in result["assets"]
                )
            )

    @patch("rapp_herdr.audit._unix_listeners", return_value=[])
    @patch("rapp_herdr.audit._unix_jobs", return_value=[])
    @patch("rapp_herdr.audit._herdr_snapshot", return_value={})
    def test_audit_omits_secret_and_symlink_escape_manifests(
        self, _herdr, _jobs, _listeners
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            twins = home / ".rapp" / "twins"
            outside = home / "outside" / "rappid.json"
            write_json(
                outside,
                {
                    "schema": "rapp/1",
                    "rappid": "outside",
                    "kind": "twin",
                },
            )
            linked = twins / "linked"
            linked.mkdir(parents=True)
            (linked / "rappid.json").symlink_to(outside)
            write_json(
                twins / "secrets" / "rappid.json",
                {
                    "schema": "rapp/1",
                    "rappid": "secret",
                    "kind": "twin",
                },
            )
            write_json(
                twins / ".env" / "rappid.json",
                {
                    "schema": "rapp/1",
                    "rappid": "env-secret",
                    "kind": "twin",
                },
            )
            write_json(
                home / ".rapp" / "workspace-registry.json",
                {
                    "workspaces": [
                        {
                            "name": "outside",
                            "path": str(home / "outside"),
                            "rappid": "outside",
                        }
                    ]
                },
            )

            with patch("rapp_herdr.audit.Path.home", return_value=home):
                result = audit_machine(
                    {"herdr_bin": "/missing", "session": "rapp-estate"},
                    assigned_rappids=set(),
                )

            paths = {asset.get("path") for asset in result["assets"]}
            self.assertNotIn(str(outside), paths)
            self.assertFalse(any("secrets" in str(path) for path in paths))
            self.assertFalse(any(".env" in str(path) for path in paths))
            self.assertFalse(
                any(asset.get("type") == "workspace-pointer" for asset in result["assets"])
            )


if __name__ == "__main__":
    unittest.main()
