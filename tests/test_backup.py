from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapp_herdr.backup import (
    BACKUP_SCHEMA,
    export_estate_backup,
    import_estate_backup,
)
from rapp_herdr.model import RappHerdrError

from tests.test_estate import create_estate


class EstateBackupTests(unittest.TestCase):
    def test_backup_round_trip_replaces_manifest_and_keeps_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            backup = export_estate_backup(manifest)
            original = manifest.read_bytes()
            backup["estate"]["name"] = "Restored Estate"
            plain_manifest = backup["estate"]

            result = import_estate_backup(manifest, plain_manifest)

            self.assertTrue(result["ok"])
            self.assertEqual(result["estate"], "Restored Estate")
            self.assertEqual(
                json.loads(manifest.read_text())["name"],
                "Restored Estate",
            )
            rollback = Path(result["previous_manifest"])
            self.assertEqual(rollback.read_bytes(), original)
            self.assertEqual(rollback.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)

    def test_exported_backup_detects_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            backup = export_estate_backup(manifest)
            self.assertEqual(backup["schema"], BACKUP_SCHEMA)
            before = manifest.read_bytes()
            backup["estate"]["name"] = "Tampered"

            with self.assertRaisesRegex(RappHerdrError, "checksum"):
                import_estate_backup(manifest, backup)

            self.assertEqual(manifest.read_bytes(), before)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_invalid_import_never_replaces_current_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()

            with self.assertRaisesRegex(RappHerdrError, "schema"):
                import_estate_backup(
                    manifest,
                    {"schema": "not-an-estate", "devices": []},
                )

            self.assertEqual(manifest.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
