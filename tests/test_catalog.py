from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.catalog import CatalogManager, discover_catalogs
from rapp_herdr.cell import run_cell
from rapp_herdr.herdr import HerdrContext
from rapp_herdr.receipts import ReceiptStore

from tests.helpers import write_json
from tests.test_manager import FakeHerdr


def create_catalog(root: Path, *, neighborhood_agent: bool = True) -> Path:
    estate = root / "test-estate"
    neighborhood = estate / "industries" / "code" / "build_bench"
    factory = neighborhood / "build_factory"
    factory.mkdir(parents=True)
    write_json(
        estate / "estate.json",
        {
            "name": "Test Estate",
            "rappid": "rappid:@test/estate:" + "a" * 64,
            "industries": [
                {
                    "id": "code",
                    "name": "Code",
                    "neighborhoods": [
                        {
                            "id": "build_bench",
                            "name": "Build Bench",
                            "factories": [
                                {"id": "build_factory", "name": "Build Factory"}
                            ],
                        }
                    ],
                }
            ],
        },
    )
    (factory / "agent.py").write_text(
        "def perform_root(text): return {'response': 'factory:' + text}\n",
        encoding="utf-8",
    )
    if neighborhood_agent:
        (neighborhood / "agent.py").write_text(
            "def perform_root(text): return {'response': 'neighborhood:' + text}\n",
            encoding="utf-8",
        )
    return estate


def add_second_factory(estate: Path) -> None:
    neighborhood = estate / "industries" / "code" / "build_bench"
    second = neighborhood / "qa_factory"
    second.mkdir()
    (second / "agent.py").write_text(
        "def perform_root(text): return {'response': 'qa:' + text}\n",
        encoding="utf-8",
    )
    manifest = json.loads((estate / "estate.json").read_text())
    manifest["industries"][0]["neighborhoods"][0]["factories"].append(
        {"id": "qa_factory", "name": "QA Factory"}
    )
    write_json(estate / "estate.json", manifest)


class CatalogHerdr(FakeHerdr):
    def run_pane(self, pane_id, command):
        self.commands.append(("run", pane_id, command))
        self.pane_values[pane_id]["agent"] = "rapp-neighborhood"
        self.pane_values[pane_id]["agent_status"] = "idle"


class FakeReporter:
    def __init__(self, **_kwargs):
        self.states = []

    def start(self, **_kwargs):
        return None

    def state(self, state, message="", **_kwargs):
        self.states.append((state, message))

    def release(self):
        return None


class CatalogTests(unittest.TestCase):
    def test_catalog_discovers_one_worker_per_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_catalog(Path(directory))

            catalogs = discover_catalogs([directory])

            self.assertEqual(len(catalogs), 1)
            self.assertEqual(len(catalogs[0].cells), 1)
            self.assertEqual(catalogs[0].cells[0].default_agent, "neighborhood")
            self.assertEqual(
                set(catalogs[0].cells[0].agents),
                {"neighborhood", "build_factory"},
            )

    def test_catalog_falls_back_to_single_factory_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_catalog(Path(directory), neighborhood_agent=False)

            cell = discover_catalogs([directory])[0].cells[0]

            self.assertEqual(cell.default_agent, "build_factory")
            self.assertEqual(list(cell.agents), ["build_factory"])

    def test_catalog_generates_router_for_multi_factory_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = create_catalog(Path(directory), neighborhood_agent=False)
            add_second_factory(estate)

            cell = discover_catalogs([directory])[0].cells[0]

            self.assertEqual(cell.default_agent, "__router__")
            self.assertEqual(set(cell.agents), {"build_factory", "qa_factory"})

    @patch("rapp_herdr.cell.HerdrReporter", FakeReporter)
    def test_cell_runs_plain_text_through_default_neighborhood_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = create_catalog(Path(directory))
            cell = discover_catalogs([directory])[0].cells[0]
            payload = {
                "workspace": str(cell.workspace),
                "label": cell.label,
                "estate": "Test Estate",
                "session_id": "rapp-herdr-cell:test",
                "agents": cell.agents,
                "default_agent": cell.default_agent,
                "herdr_bin": "/opt/herdr",
            }
            output = io.StringIO()

            with patch(
                "sys.stdin",
                io.StringIO("hello\nbuild_factory: direct\n/quit\n"),
            ):
                with redirect_stdout(output):
                    result = run_cell(payload)

            self.assertEqual(result, 0)
            self.assertIn("neighborhood:hello", output.getvalue())
            self.assertIn("factory:direct", output.getvalue())

    def test_catalog_manager_projects_estate_workspace_and_tab(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_catalog(Path(directory))
            client = CatalogHerdr()
            client.context_value = HerdrContext((0, 7, 4), "/tmp/catalog.sock")
            manager = CatalogManager(client, ReceiptStore(Path(directory) / "state"))

            result = manager.up([directory])

            self.assertTrue(result["ok"])
            self.assertEqual(result["estates"][0]["state"], "running")
            self.assertEqual(client.workspace["label"], "RAPP Estate: Test Estate")
            self.assertEqual(len(client.pane_values), 1)

            client.pane_values["w1:p1"].pop("agent")
            degraded = manager.status([directory])
            self.assertEqual(degraded["estates"][0]["state"], "degraded")
            self.assertTrue(degraded["estates"][0]["managed"])

            restarted = manager.up([directory])
            self.assertEqual(restarted["estates"][0]["state"], "running")

            client.pane_values["w1:p1"].pop("agent")
            down = manager.down([directory])
            self.assertTrue(down["ok"])
            self.assertEqual(client.closed, ["w1"])

    def test_catalog_status_rejects_changed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = create_catalog(Path(directory))
            client = CatalogHerdr()
            client.context_value = HerdrContext((0, 7, 4), "/tmp/catalog.sock")
            manager = CatalogManager(client, ReceiptStore(Path(directory) / "state"))
            manager.up([directory])
            value = json.loads((estate / "estate.json").read_text())
            value["rappid"] = "rappid:@test/changed:" + "b" * 64
            write_json(estate / "estate.json", value)

            status = manager.status([directory])

            self.assertFalse(status["ok"])
            self.assertEqual(status["estates"][0]["state"], "diverged")

    def test_stopped_catalog_status_keeps_cell_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_catalog(Path(directory))
            client = CatalogHerdr()
            client.context_value = HerdrContext((0, 7, 4), "/tmp/catalog.sock")
            manager = CatalogManager(client, ReceiptStore(Path(directory) / "state"))

            status = manager.status([directory])

            cells = status["estates"][0]["cells"]
            self.assertEqual(len(cells), 1)
            self.assertEqual(cells[0]["label"], "Build Bench")
            self.assertEqual(cells[0]["agent_status"], "stopped")

    def test_missing_catalog_source_is_reported_and_can_be_torn_down(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = create_catalog(Path(directory))
            client = CatalogHerdr()
            client.context_value = HerdrContext((0, 7, 4), "/tmp/catalog.sock")
            manager = CatalogManager(client, ReceiptStore(Path(directory) / "state"))
            manager.up([directory])
            shutil.rmtree(estate)

            status = manager.status([directory])
            down = manager.down([directory])

            self.assertFalse(status["ok"])
            self.assertEqual(status["estates"][0]["state"], "source-missing")
            self.assertTrue(down["ok"])
            self.assertEqual(client.closed, ["w1"])

    def test_stale_workspace_receipt_is_removed_by_down(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            create_catalog(Path(directory))
            client = CatalogHerdr()
            client.context_value = HerdrContext((0, 7, 4), "/tmp/catalog.sock")
            state = ReceiptStore(Path(directory) / "state")
            manager = CatalogManager(client, state)
            manager.up([directory])
            client.workspace = None
            client.pane_values = {}

            down = manager.down([directory])

            self.assertTrue(down["ok"])
            self.assertEqual(down["estates"][0]["reason"], "removed stale receipt")

    @patch("rapp_herdr.cell.HerdrReporter", FakeReporter)
    def test_generated_router_accepts_plain_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            estate = create_catalog(Path(directory), neighborhood_agent=False)
            add_second_factory(estate)
            cell = discover_catalogs([directory])[0].cells[0]
            payload = {
                "workspace": str(cell.workspace),
                "label": cell.label,
                "estate": "Test Estate",
                "session_id": "rapp-herdr-cell:test",
                "agents": cell.agents,
                "default_agent": cell.default_agent,
                "herdr_bin": "/opt/herdr",
            }
            output = io.StringIO()

            with patch("sys.stdin", io.StringIO("qa this output\n/quit\n")):
                with redirect_stdout(output):
                    result = run_cell(payload)

            self.assertEqual(result, 0)
            self.assertIn("routed -> qa_factory", output.getvalue())
            self.assertIn("qa:qa this output", output.getvalue())


if __name__ == "__main__":
    unittest.main()
