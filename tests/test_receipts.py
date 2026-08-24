from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from rapp_herdr.model import load_neighborhood
from rapp_herdr.model import RappHerdrError
from rapp_herdr.receipts import RECEIPT_SCHEMA, ReceiptStore

from tests.helpers import create_neighborhood


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_atomic_private_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, _ = create_neighborhood(root / "neighborhood")
            neighborhood = load_neighborhood(manifest)
            store = ReceiptStore(root / "state")
            path = store.path_for(neighborhood, "/tmp/herdr.sock")
            value = {"schema": RECEIPT_SCHEMA, "state": "running"}

            store.write(path, value)

            self.assertEqual(store.load(path), value)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_operation_lock_excludes_a_concurrent_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, _ = create_neighborhood(root / "neighborhood")
            neighborhood = load_neighborhood(manifest)
            store = ReceiptStore(root / "state")
            path = store.path_for(neighborhood, "/tmp/herdr.sock")

            with store.operation_lock(path):
                with self.assertRaisesRegex(RappHerdrError, "another neighborhood"):
                    with store.operation_lock(path):
                        self.fail("concurrent lock unexpectedly succeeded")

            with store.operation_lock(path) as token:
                self.assertTrue(token)

    def test_waiting_environment_lock_serializes_callers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ReceiptStore(Path(directory) / "state")
            path = Path(directory) / "python-environment.json"
            acquired = threading.Event()

            def waiter() -> None:
                with store.operation_lock(path, wait_timeout=1):
                    acquired.set()

            with store.operation_lock(path):
                thread = threading.Thread(target=waiter)
                thread.start()
                time.sleep(0.1)
                self.assertFalse(acquired.is_set())

            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertTrue(acquired.is_set())


if __name__ == "__main__":
    unittest.main()
