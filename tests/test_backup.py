from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapp_herdr.backup import export_estate_backup, import_estate_backup
from rapp_herdr.model import RappHerdrError

from tests.test_estate import create_estate


class BackupTests(unittest.TestCase):
    def test_export_and_import_preserve_valid_estate_with_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            backup = export_estate_backup(manifest)
            original = json.loads(manifest.read_text())

            result = import_estate_backup(manifest, backup)

            self.assertTrue(result["ok"])
            self.assertEqual(json.loads(manifest.read_text()), original)
            self.assertTrue(Path(result["previous_manifest"]).is_file())

    def test_import_rejects_tampered_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            backup = export_estate_backup(manifest)
            backup["estate"]["name"] = "Tampered"

            with self.assertRaisesRegex(RappHerdrError, "checksum"):
                import_estate_backup(manifest, backup)


if __name__ == "__main__":
    unittest.main()
