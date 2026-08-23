from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.backup import (
    export_estate_backup,
    import_estate_backup,
    replace_estate_manifest,
)
from rapp_herdr.model import RappHerdrError
from rapp_herdr.receipts import ReceiptStore

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

    def test_ui_import_rejects_raw_unchecksummed_estate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            raw = json.loads(manifest.read_text())

            with self.assertRaisesRegex(RappHerdrError, "backup must use schema"):
                import_estate_backup(manifest, raw)

    def test_expected_hash_is_rechecked_inside_manifest_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            expected_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
            replacement = json.loads(manifest.read_text())
            replacement["name"] = "Buddy writer"
            concurrent = json.loads(manifest.read_text())
            concurrent["name"] = "Concurrent writer"

            @contextmanager
            def racing_lock(_store, _path, *, wait_timeout=0):
                self.assertEqual(wait_timeout, 30)
                manifest.write_text(json.dumps(concurrent))
                yield "test-lock"

            with patch.object(
                ReceiptStore,
                "operation_lock",
                racing_lock,
            ):
                with self.assertRaisesRegex(
                    RappHerdrError,
                    "changed before replacement",
                ):
                    replace_estate_manifest(
                        manifest,
                        replacement,
                        expected_hash=expected_hash,
                    )

            self.assertEqual(
                json.loads(manifest.read_text())["name"],
                "Concurrent writer",
            )


if __name__ == "__main__":
    unittest.main()
