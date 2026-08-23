from __future__ import annotations

import tempfile
import threading
import unittest
import sys
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.herdr import HerdrContext, HerdrPane
from rapp_herdr.lifecycle import LAUNCH_HEADER
from rapp_herdr.manager import NeighborhoodManager
from rapp_herdr.model import RappHerdrError, load_neighborhood, resolve_topology
from rapp_herdr.receipts import ReceiptStore

from tests.helpers import create_neighborhood, create_twin


class FakeHerdr:
    def __init__(self):
        self.binary = "/custom/herdr"
        self.context_value = HerdrContext((0, 7, 4), "/tmp/herdr-test.sock")
        self.workspace = None
        self.pane_values = {}
        self.commands = []
        self.created_tabs = 0
        self.closed = []
        self.fail_run_at = None
        self.fail_exception = RappHerdrError("injected pane failure")

    def context(self):
        return self.context_value

    def create_workspace(self, cwd, label):
        self.workspace = {
            "workspace_id": "w1",
            "label": label,
            "cwd": str(cwd),
        }
        pane = HerdrPane("w1", "w1:t1", "w1:p1", "term_1")
        self.pane_values[pane.pane_id] = {
            "workspace_id": "w1",
            "tab_id": pane.tab_id,
            "pane_id": pane.pane_id,
            "terminal_id": pane.terminal_id,
            "cwd": str(cwd),
            "agent_status": "unknown",
        }
        return pane

    def rename_tab(self, tab_id, label):
        self.commands.append(("rename", tab_id, label))

    def create_tab(self, workspace_id, cwd, label):
        self.created_tabs += 1
        index = self.created_tabs + 1
        pane = HerdrPane(
            workspace_id,
            f"w1:t{index}",
            f"w1:p{index}",
            f"term_{index}",
        )
        self.pane_values[pane.pane_id] = {
            "workspace_id": workspace_id,
            "tab_id": pane.tab_id,
            "pane_id": pane.pane_id,
            "terminal_id": pane.terminal_id,
            "cwd": str(cwd),
            "agent_status": "unknown",
        }
        return pane

    def run_pane(self, pane_id, command):
        self.commands.append(("run", pane_id, command))
        run_count = sum(1 for item in self.commands if item[0] == "run")
        if self.fail_run_at == run_count:
            raise self.fail_exception
        self.pane_values[pane_id]["agent"] = "rapp-twin"
        self.pane_values[pane_id]["agent_status"] = "idle"

    def pane(self, pane_id):
        return dict(self.pane_values[pane_id])

    def read_pane(self, pane_id, lines=80):
        return f"pane {pane_id}"

    def workspaces(self):
        return (dict(self.workspace),) if self.workspace else ()

    def panes(self, workspace_id):
        return tuple(
            dict(value)
            for value in self.pane_values.values()
            if value["workspace_id"] == workspace_id
        )

    def close_workspace(self, workspace_id):
        self.closed.append(workspace_id)
        self.workspace = None
        self.pane_values = {}


class ManagerTests(unittest.TestCase):
    def _topology(self, root: Path):
        manifest, rappids = create_neighborhood(root / "neighborhood")
        estate = root / "estate"
        for index, rappid in enumerate(rappids, 1):
            create_twin(estate, f"twin-{index}", rappid)
        return resolve_topology(
            load_neighborhood(manifest),
            [estate],
            require_all_local=True,
        )

    def test_health_requires_the_launch_nonce(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header(LAUNCH_HEADER, "expected")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            self.assertTrue(NeighborhoodManager._health(url, "expected"))
            self.assertFalse(NeighborhoodManager._health(url, "another-twin"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    def test_blocked_pane_is_not_accepted_from_foreign_health(
        self, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = FakeHerdr()
            client.pane_values["w1:p1"] = {
                "workspace_id": "w1",
                "pane_id": "w1:p1",
                "cwd": directory,
                "agent": "rapp-twin",
                "agent_status": "blocked",
            }
            manager = NeighborhoodManager(
                client,
                ReceiptStore(Path(directory) / "state"),
            )

            with self.assertRaisesRegex(RappHerdrError, "blocked"):
                manager._wait_until_ready("w1:p1", 7081, "expected", timeout=0.1)

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    @patch("rapp_herdr.manager.allocate_ports", return_value=(7081, 7082, 7083, 7084))
    @patch(
        "rapp_herdr.manager.prepare_brainstem_python",
        return_value=Path("/tmp/python"),
    )
    @patch("rapp_herdr.manager._internal_twin_command", return_value="run-twin")
    def test_four_twins_create_one_workspace_and_four_tabs(
        self, internal_command, _prepare, _ports, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = self._topology(root)
            client = FakeHerdr()
            manager = NeighborhoodManager(client, ReceiptStore(root / "state"))

            result = manager.up(topology, base_port=7081)

            self.assertTrue(result["managed"])
            self.assertEqual(len(result["members"]), 4)
            self.assertEqual(client.created_tabs, 3)
            self.assertEqual(
                len([item for item in client.commands if item[0] == "run"]),
                4,
            )
            self.assertEqual(internal_command.call_count, 4)
            self.assertTrue(
                all(
                    call.kwargs["herdr_binary"] == "/custom/herdr"
                    for call in internal_command.call_args_list
                )
            )

            second = manager.up(topology, base_port=7081)
            self.assertTrue(second["managed"])
            self.assertEqual(client.created_tabs, 3)

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    @patch("rapp_herdr.manager.allocate_ports", return_value=(7081, 7082, 7083, 7084))
    @patch(
        "rapp_herdr.manager.prepare_brainstem_python",
        return_value=Path("/tmp/python"),
    )
    def test_existing_workspace_rejects_changed_member_order(
        self, _prepare, _ports, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = self._topology(root)
            client = FakeHerdr()
            manager = NeighborhoodManager(client, ReceiptStore(root / "state"))
            manager.up(topology, base_port=7081)
            changed = replace(topology, twins=tuple(reversed(topology.twins)))

            with self.assertRaisesRegex(RappHerdrError, "topology"):
                manager.up(changed, base_port=7081)

            self.assertEqual(client.created_tabs, 3)

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    @patch("rapp_herdr.manager.allocate_ports", return_value=(7081, 7082, 7083, 7084))
    @patch(
        "rapp_herdr.manager.prepare_brainstem_python",
        return_value=Path(sys.executable),
    )
    def test_existing_workspace_restarts_stopped_twin(
        self, _prepare, _ports, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = self._topology(root)
            client = FakeHerdr()
            manager = NeighborhoodManager(client, ReceiptStore(root / "state"))
            manager.up(topology, base_port=7081)
            initial_runs = len(
                [item for item in client.commands if item[0] == "run"]
            )
            client.pane_values["w1:p1"].pop("agent")

            degraded = manager.status(topology.neighborhood)
            restarted = manager.up(topology, base_port=7081)

            self.assertEqual(degraded["state"], "degraded")
            self.assertTrue(degraded["managed"])
            self.assertEqual(restarted["state"], "running")
            self.assertEqual(
                len([item for item in client.commands if item[0] == "run"]),
                initial_runs + 1,
            )

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    @patch("rapp_herdr.manager.allocate_ports", return_value=(7081, 7082, 7083, 7084))
    @patch(
        "rapp_herdr.manager.prepare_brainstem_python",
        return_value=Path("/tmp/python"),
    )
    def test_partial_start_failure_rolls_back_only_created_workspace(
        self, _prepare, _ports, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = self._topology(root)
            client = FakeHerdr()
            client.fail_run_at = 2
            store = ReceiptStore(root / "state")
            manager = NeighborhoodManager(client, store)

            with self.assertRaisesRegex(RappHerdrError, "injected pane failure"):
                manager.up(topology, base_port=7081)

            self.assertEqual(client.closed, ["w1"])
            receipt_path = store.path_for(
                topology.neighborhood, client.context_value.socket_path
            )
            self.assertFalse(receipt_path.exists())

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    @patch("rapp_herdr.manager.allocate_ports", return_value=(7081, 7082, 7083, 7084))
    @patch(
        "rapp_herdr.manager.prepare_brainstem_python",
        return_value=Path("/tmp/python"),
    )
    def test_interrupt_rolls_back_started_twins_before_propagating(
        self, _prepare, _ports, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = self._topology(root)
            client = FakeHerdr()
            client.fail_run_at = 2
            client.fail_exception = KeyboardInterrupt()
            store = ReceiptStore(root / "state")
            manager = NeighborhoodManager(client, store)

            with self.assertRaises(KeyboardInterrupt):
                manager.up(topology, base_port=7081)

            self.assertEqual(client.closed, ["w1"])
            receipt_path = store.path_for(
                topology.neighborhood, client.context_value.socket_path
            )
            self.assertFalse(receipt_path.exists())

    @patch("rapp_herdr.manager.NeighborhoodManager._health", return_value=True)
    @patch("rapp_herdr.manager.allocate_ports", return_value=(7081, 7082, 7083, 7084))
    @patch(
        "rapp_herdr.manager.prepare_brainstem_python",
        return_value=Path("/tmp/python"),
    )
    def test_down_refuses_workspace_with_unowned_extra_pane(
        self, _prepare, _ports, _health
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = self._topology(root)
            client = FakeHerdr()
            manager = NeighborhoodManager(client, ReceiptStore(root / "state"))
            manager.up(topology, base_port=7081)
            client.pane_values["w1:p-extra"] = {
                "workspace_id": "w1",
                "pane_id": "w1:p-extra",
                "cwd": str(root),
                "agent_status": "unknown",
            }

            status = manager.status(topology.neighborhood)
            self.assertFalse(status["managed"])
            self.assertEqual(status["state"], "diverged")

            with self.assertRaisesRegex(RappHerdrError, "pane set differs"):
                manager.down(topology.neighborhood)

            self.assertEqual(client.closed, [])


if __name__ == "__main__":
    unittest.main()
