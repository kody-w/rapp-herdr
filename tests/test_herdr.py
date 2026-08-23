from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.herdr import HerdrClient
from rapp_herdr.model import RappHerdrError


class HerdrClientTests(unittest.TestCase):
    @patch("rapp_herdr.herdr.subprocess.run")
    def test_context_requires_running_compatible_server(self, run) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["herdr", "status"],
            0,
            stdout=(
                "client:\n"
                "  version: 0.7.4\n"
                "server:\n"
                "  status: running\n"
                "  version: 0.7.4\n"
                "  compatible: yes\n"
                "  socket: /tmp/herdr.sock\n"
            ),
            stderr="",
        )

        context = HerdrClient(binary="/bin/herdr").context()

        self.assertEqual(context.version, (0, 7, 4))
        self.assertEqual(context.socket_path, "/tmp/herdr.sock")

    @patch("rapp_herdr.herdr.subprocess.run")
    def test_create_workspace_uses_opaque_ids_from_response(self, run) -> None:
        response = {
            "result": {
                "workspace": {"workspace_id": "wz"},
                "root_pane": {
                    "workspace_id": "wz",
                    "tab_id": "wz:tq",
                    "pane_id": "wz:pr",
                    "terminal_id": "term_xyz",
                },
            }
        }
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(response), stderr=""
        )

        pane = HerdrClient(binary="/bin/herdr").create_workspace(
            Path("/tmp/twin"), "Neighborhood"
        )

        self.assertEqual(pane.workspace_id, "wz")
        self.assertEqual(pane.tab_id, "wz:tq")
        self.assertEqual(pane.pane_id, "wz:pr")

    @patch("rapp_herdr.herdr.subprocess.run")
    def test_nonzero_cli_exit_is_not_success_shaped(self, run) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="connection refused"
        )

        with self.assertRaisesRegex(RappHerdrError, "connection refused"):
            HerdrClient(binary="/bin/herdr").workspaces()

    def test_relative_explicit_binary_is_stored_as_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "herdr"
            executable.write_text("", encoding="utf-8")
            previous = Path.cwd()
            os.chdir(root)
            try:
                client = HerdrClient(binary="./herdr")
            finally:
                os.chdir(previous)

            self.assertEqual(client.binary, str(executable.resolve()))

    @patch("rapp_herdr.herdr.subprocess.run")
    def test_pane_read_returns_raw_terminal_text(self, run) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="raw pane output\n", stderr=""
        )

        output = HerdrClient(binary="/bin/herdr").read_pane("w1:p1")

        self.assertEqual(output, "raw pane output\n")


if __name__ == "__main__":
    unittest.main()
