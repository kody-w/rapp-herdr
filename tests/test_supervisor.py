from __future__ import annotations

import signal
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.supervisor import _bootstrap_artifact, _forward_signal


class FakeChild:
    def __init__(self):
        self.terminated = 0
        self.signals = []

    def poll(self):
        return None

    def terminate(self):
        self.terminated += 1

    def send_signal(self, signum):
        self.signals.append(signum)


class SupervisorTests(unittest.TestCase):
    def test_bootstrap_artifact_contains_only_rapp_herdr_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(
                "os.environ",
                {"RAPP_HERDR_BOOTSTRAP_ROOT": directory},
                clear=False,
            ):
                artifact = _bootstrap_artifact()

            self.assertEqual(artifact.parent, Path(directory))
            with zipfile.ZipFile(artifact) as bundle:
                names = bundle.namelist()
                self.assertIn("rapp_herdr/bootstrap.py", names)
                self.assertTrue(
                    all(name.startswith("rapp_herdr/") for name in names)
                )
                self.assertIsNone(bundle.testzip())

    def test_windows_signal_uses_supported_terminate_path(self) -> None:
        child = FakeChild()

        _forward_signal(child, signal.SIGINT, windows=True)

        self.assertEqual(child.terminated, 1)
        self.assertEqual(child.signals, [])

    def test_posix_signal_is_forwarded_without_termination(self) -> None:
        child = FakeChild()

        _forward_signal(child, signal.SIGINT, windows=False)

        self.assertEqual(child.terminated, 0)
        self.assertEqual(child.signals, [signal.SIGINT])


if __name__ == "__main__":
    unittest.main()
