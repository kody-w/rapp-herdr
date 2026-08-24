from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .cell import CELL_PAYLOAD_SCHEMA
from .herdr import HerdrClient, HerdrPane
from .manager import _shell_command
from .model import RappHerdrError
from .receipts import ReceiptStore

CATALOG_RECEIPT_SCHEMA = "rapp-herdr-catalog-receipt/1.0"


@dataclass(frozen=True)
class CatalogCell:
    id: str
    label: str
    workspace: Path
    agents: dict[str, str]
    default_agent: str | None


@dataclass(frozen=True)
class EstateCatalog:
    id: str
    name: str
    rappid: str
    root: Path
    cells: tuple[CatalogCell, ...]


def _load_estate_catalog(path: Path) -> EstateCatalog:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid estate catalog {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"estate catalog must contain an object: {path}")
    root = path.parent.resolve()
    estate_id = root.name
    name = value.get("name")
    rappid = value.get("rappid")
    if not isinstance(name, str) or not name:
        raise RappHerdrError(f"estate catalog has no name: {path}")
    if not isinstance(rappid, str) or not rappid:
        raise RappHerdrError(f"estate catalog has no rappid: {path}")
    cells: list[CatalogCell] = []
    industries = value.get("industries", [])
    if not isinstance(industries, list):
        raise RappHerdrError(f"estate industries must be an array: {path}")
    for industry in industries:
        if not isinstance(industry, dict):
            continue
        industry_id = industry.get("id")
        neighborhoods = industry.get("neighborhoods", [])
        if not isinstance(industry_id, str) or not isinstance(neighborhoods, list):
            continue
        for neighborhood in neighborhoods:
            if not isinstance(neighborhood, dict):
                continue
            neighborhood_id = neighborhood.get("id")
            label = neighborhood.get("name")
            if not isinstance(neighborhood_id, str) or not isinstance(label, str):
                continue
            workspace = (root / "industries" / industry_id / neighborhood_id).resolve()
            if workspace != root and root not in workspace.parents:
                raise RappHerdrError(
                    f"catalog neighborhood escapes estate root: {workspace}"
                )
            agents: dict[str, str] = {}
            neighborhood_agent = workspace / "agent.py"
            default_agent: str | None = None
            if neighborhood_agent.is_file():
                agents["neighborhood"] = str(neighborhood_agent)
                default_agent = "neighborhood"
            factories = neighborhood.get("factories", [])
            if isinstance(factories, list):
                for factory in factories:
                    if not isinstance(factory, dict):
                        continue
                    factory_id = factory.get("id")
                    if not isinstance(factory_id, str):
                        continue
                    agent = workspace / factory_id / "agent.py"
                    if agent.is_file():
                        agents[factory_id] = str(agent)
            if default_agent is None and len(agents) == 1:
                default_agent = next(iter(agents))
            elif default_agent is None and len(agents) > 1:
                default_agent = "__router__"
            if not agents:
                continue
            cells.append(
                CatalogCell(
                    id=f"{industry_id}/{neighborhood_id}",
                    label=label,
                    workspace=workspace,
                    agents=agents,
                    default_agent=default_agent,
                )
            )
    return EstateCatalog(
        id=estate_id,
        name=name,
        rappid=rappid,
        root=root,
        cells=tuple(cells),
    )


def discover_catalogs(roots: Iterable[str | Path]) -> tuple[EstateCatalog, ...]:
    manifests: set[Path] = set()
    for raw_root in roots:
        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            raise RappHerdrError(f"estate catalog root is unavailable: {root}")
        if (root / "estate.json").is_file():
            manifests.add(root / "estate.json")
        else:
            manifests.update(root.glob("*/estate.json"))
    catalogs = tuple(
        _load_estate_catalog(path)
        for path in sorted(manifests)
    )
    ids = [catalog.id for catalog in catalogs]
    if len(ids) != len(set(ids)):
        raise RappHerdrError("estate catalog ids must be unique across roots")
    return catalogs


def _cell_command(
    payload_file: Path,
) -> str:
    source_root = Path(__file__).resolve().parents[1]
    code = (
        "import sys; "
        "sys.path.insert(0, sys.argv.pop(1)); "
        "from rapp_herdr.cli import main; "
        "raise SystemExit(main(sys.argv[1:]))"
    )
    return _shell_command(
        [
            sys.executable,
            "-c",
            code,
            str(source_root),
            "_cell",
            "--payload-file",
            str(payload_file),
        ]
    )


class CatalogManager:
    def __init__(self, client: HerdrClient, receipts: ReceiptStore):
        self.client = client
        self.receipts = receipts

    def _path(self, catalog: EstateCatalog, socket_path: str) -> Path:
        digest = hashlib.sha256(
            f"{socket_path}\0{catalog.root}".encode()
        ).hexdigest()[:32]
        return self.receipts.root / "catalogs" / f"{digest}.json"

    def _receipts_for_socket(
        self,
        socket_path: str,
    ) -> tuple[tuple[Path, dict[str, Any]], ...]:
        directory = self.receipts.root / "catalogs"
        if not directory.is_dir():
            return ()
        values = []
        for path in sorted(directory.glob("*.json")):
            receipt = self.receipts.load(
                path,
                schema=CATALOG_RECEIPT_SCHEMA,
            )
            herdr = receipt.get("herdr") if receipt else None
            if (
                receipt is not None
                and isinstance(herdr, dict)
                and herdr.get("socket") == socket_path
            ):
                values.append((path, receipt))
        return tuple(values)

    @staticmethod
    def _remove_payloads(receipt: dict[str, Any]) -> None:
        for cell in receipt.get("cells", []):
            if isinstance(cell, dict):
                payload = cell.get("payload_file")
                if isinstance(payload, str) and payload:
                    Path(payload).unlink(missing_ok=True)

    def _close_receipt(
        self,
        receipt_path: Path,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        estate_id = str(receipt.get("estate") or "unknown")
        status = self._status_receipt(receipt)
        if status.get("state") == "stale":
            self._remove_payloads(receipt)
            self.receipts.delete(receipt_path)
            return {
                "estate": estate_id,
                "ok": True,
                "state": "down",
                "reason": "removed stale receipt",
            }
        if not status.get("managed"):
            return {
                "estate": estate_id,
                "ok": False,
                "error": "catalog workspace ownership diverged",
            }
        self.client.close_workspace(str(status["workspace_id"]))
        self._remove_payloads(receipt)
        self.receipts.delete(receipt_path)
        return {"estate": estate_id, "ok": True, "state": "down"}

    def _cell_payload_path(
        self,
        catalog: EstateCatalog,
        cell: CatalogCell,
    ) -> Path:
        digest = hashlib.sha256(
            f"{catalog.root}\0{cell.id}".encode()
        ).hexdigest()
        return self.receipts.root / "cells" / f"{digest}.json"

    def _write_cell_payload(
        self,
        catalog: EstateCatalog,
        cell: CatalogCell,
    ) -> Path:
        session_hash = hashlib.sha256(
            f"{catalog.rappid}\0{cell.id}".encode()
        ).hexdigest()
        path = self._cell_payload_path(catalog, cell)
        self.receipts.write(
            path,
            {
                "schema": CELL_PAYLOAD_SCHEMA,
                "workspace": str(cell.workspace),
                "label": cell.label,
                "estate": catalog.name,
                "session_id": f"rapp-herdr-cell:{session_hash}",
                "agents": cell.agents,
                "default_agent": cell.default_agent,
                "herdr_bin": self.client.binary,
            },
            schema=CELL_PAYLOAD_SCHEMA,
        )
        return path

    @staticmethod
    def _signature(catalog: EstateCatalog) -> dict[str, Any]:
        return {
            "id": catalog.id,
            "name": catalog.name,
            "rappid": catalog.rappid,
            "cells": [
                {
                    "id": cell.id,
                    "label": cell.label,
                    "workspace": str(cell.workspace),
                    "default_agent": cell.default_agent,
                    "agents": [
                        [name, path]
                        for name, path in sorted(cell.agents.items())
                    ],
                }
                for cell in catalog.cells
            ],
        }

    def _wait(self, pane_id: str, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pane = self.client.pane(pane_id)
            if pane.get("agent") == "rapp-neighborhood":
                return
            time.sleep(0.1)
        output = self.client.read_pane(pane_id, lines=80)
        raise RappHerdrError(
            f"neighborhood worker did not start in {pane_id}"
            + (f":\n{output}" if output else "")
        )

    def _status_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        herdr = receipt.get("herdr")
        cells = receipt.get("cells")
        if not isinstance(herdr, dict) or not isinstance(cells, list):
            raise RappHerdrError("invalid catalog receipt")
        workspace_id = herdr.get("workspace_id")
        if not isinstance(workspace_id, str):
            raise RappHerdrError("catalog receipt has no workspace id")
        workspaces = {
            workspace.get("workspace_id"): workspace
            for workspace in self.client.workspaces()
        }
        workspace = workspaces.get(workspace_id)
        if workspace is None:
            return {
                "ok": False,
                "state": "stale",
                "managed": False,
                "workspace_id": workspace_id,
            }
        panes = {
            pane.get("pane_id"): pane
            for pane in self.client.panes(workspace_id)
        }
        expected = {
            cell.get("pane_id")
            for cell in cells
            if isinstance(cell, dict)
        }
        owned = (
            workspace.get("label") == herdr.get("workspace_label")
            and set(panes) == expected
        )
        all_live = True
        statuses = []
        for cell in cells:
            if not isinstance(cell, dict):
                owned = False
                continue
            pane = panes.get(cell.get("pane_id"))
            matches_owner = bool(
                pane
                and pane.get("cwd") == cell.get("workspace")
                and pane.get("terminal_id") == cell.get("terminal_id")
            )
            live = bool(pane and pane.get("agent") == "rapp-neighborhood")
            owned = owned and matches_owner
            all_live = all_live and live
            statuses.append(
                {
                    "id": cell.get("id"),
                    "label": cell.get("label"),
                    "pane_id": cell.get("pane_id"),
                    "agent_status": pane.get("agent_status") if pane else "missing",
                    "managed": matches_owner,
                    "live": live,
                }
            )
        return {
            "ok": owned,
            "state": (
                "running"
                if owned and all_live
                else "degraded"
                if owned
                else "diverged"
            ),
            "managed": owned,
            "workspace_id": workspace_id,
            "workspace_label": herdr.get("workspace_label"),
            "cells": statuses,
        }

    def _up_one(self, catalog: EstateCatalog, socket_path: str) -> dict[str, Any]:
        if not catalog.cells:
            return {
                "ok": True,
                "estate": catalog.id,
                "state": "empty",
                "cells": [],
            }
        receipt_path = self._path(catalog, socket_path)
        with self.receipts.operation_lock(receipt_path):
            existing = self.receipts.load(
                receipt_path,
                schema=CATALOG_RECEIPT_SCHEMA,
            )
            if existing is not None:
                if existing.get("signature") != self._signature(catalog):
                    raise RappHerdrError(
                        f"estate catalog changed for {catalog.id}; run down, then up"
                    )
                status = self._status_receipt(existing)
                if not status.get("managed"):
                    raise RappHerdrError(
                        f"estate catalog ownership diverged for {catalog.id}"
                    )
                cells_by_id = {cell.id: cell for cell in catalog.cells}
                records_by_id = {
                    record.get("id"): record
                    for record in existing.get("cells", [])
                    if isinstance(record, dict)
                }
                for cell_status in status.get("cells", []):
                    if cell_status.get("live"):
                        continue
                    cell_id = cell_status.get("id")
                    cell = cells_by_id.get(cell_id)
                    record = records_by_id.get(cell_id)
                    if cell is None or record is None:
                        raise RappHerdrError(
                            f"cannot restart unknown catalog cell {cell_id!r}"
                        )
                    payload_path = self._write_cell_payload(catalog, cell)
                    record["payload_file"] = str(payload_path)
                    self.client.run_pane(
                        str(record["pane_id"]),
                        _cell_command(payload_path),
                    )
                    self._wait(str(record["pane_id"]))
                self.receipts.write(
                    receipt_path,
                    existing,
                    schema=CATALOG_RECEIPT_SCHEMA,
                )
                return self._status_receipt(existing)
            root_pane: HerdrPane | None = None
            receipt: dict[str, Any] | None = None
            payload_paths: list[Path] = []
            try:
                root_pane = self.client.create_workspace(
                    catalog.cells[0].workspace,
                    f"RAPP Estate: {catalog.name}"[:160],
                )
                panes = [root_pane]
                self.client.rename_tab(root_pane.tab_id, catalog.cells[0].label)
                for cell in catalog.cells[1:]:
                    panes.append(
                        self.client.create_tab(
                            root_pane.workspace_id,
                            cell.workspace,
                            cell.label,
                        )
                    )
                cell_records = []
                for cell, pane in zip(catalog.cells, panes, strict=True):
                    payload_path = self._write_cell_payload(catalog, cell)
                    payload_paths.append(payload_path)
                    cell_records.append(
                        {
                            "id": cell.id,
                            "label": cell.label,
                            "workspace": str(cell.workspace),
                            "pane_id": pane.pane_id,
                            "tab_id": pane.tab_id,
                            "terminal_id": pane.terminal_id,
                            "payload_file": str(payload_path),
                        }
                    )
                receipt = {
                    "schema": CATALOG_RECEIPT_SCHEMA,
                    "estate": catalog.id,
                    "root": str(catalog.root),
                    "signature": self._signature(catalog),
                    "herdr": {
                        "socket": socket_path,
                        "workspace_id": root_pane.workspace_id,
                        "workspace_label": f"RAPP Estate: {catalog.name}"[:160],
                    },
                    "cells": cell_records,
                }
                self.receipts.write(
                    receipt_path,
                    receipt,
                    schema=CATALOG_RECEIPT_SCHEMA,
                )
                for cell, pane in zip(catalog.cells, panes, strict=True):
                    cell_record = next(
                        record
                        for record in cell_records
                        if record["id"] == cell.id
                    )
                    self.client.run_pane(
                        pane.pane_id,
                        _cell_command(Path(cell_record["payload_file"])),
                    )
                    self._wait(pane.pane_id)
                return self._status_receipt(receipt)
            except BaseException:
                if root_pane is not None:
                    self.client.close_workspace(root_pane.workspace_id)
                for payload_path in payload_paths:
                    payload_path.unlink(missing_ok=True)
                self.receipts.delete(receipt_path)
                raise

    def up(self, roots: Iterable[str | Path]) -> dict[str, Any]:
        context = self.client.context()
        results = []
        catalogs = discover_catalogs(roots)
        discovered_roots = {str(catalog.root) for catalog in catalogs}
        for catalog in catalogs:
            try:
                result = self._up_one(catalog, context.socket_path)
                results.append({"estate": catalog.id, **result})
            except RappHerdrError as exc:
                results.append({"estate": catalog.id, "ok": False, "error": str(exc)})
        for _path, receipt in self._receipts_for_socket(context.socket_path):
            if receipt.get("root") not in discovered_roots:
                results.append(
                    {
                        "estate": receipt.get("estate"),
                        "ok": False,
                        "state": "source-missing",
                        "error": "managed estate catalog source is no longer configured",
                    }
                )
        return {
            "ok": all(result.get("ok") for result in results),
            "estates": results,
        }

    def status(self, roots: Iterable[str | Path]) -> dict[str, Any]:
        context = self.client.context()
        results = []
        expanded_roots = [Path(root).expanduser().resolve() for root in roots]
        missing_roots = [root for root in expanded_roots if not root.is_dir()]
        catalogs = discover_catalogs(
            [root for root in expanded_roots if root.is_dir()]
        )
        discovered_roots = {str(catalog.root) for catalog in catalogs}
        seen_receipts: set[Path] = set()
        for catalog in catalogs:
            receipt_path = self._path(catalog, context.socket_path)
            seen_receipts.add(receipt_path)
            receipt = self.receipts.load(
                receipt_path,
                schema=CATALOG_RECEIPT_SCHEMA,
            )
            if receipt is None:
                results.append(
                    {
                        "estate": catalog.id,
                        "ok": True,
                        "state": "down",
                        "managed": False,
                        "cells": [
                            {
                                "id": cell.id,
                                "label": cell.label,
                                "pane_id": None,
                                "agent_status": "stopped",
                                "managed": False,
                                "live": False,
                            }
                            for cell in catalog.cells
                        ],
                    }
                )
            else:
                if receipt.get("signature") != self._signature(catalog):
                    results.append(
                        {
                            "estate": catalog.id,
                            "ok": False,
                            "state": "diverged",
                            "managed": False,
                            "error": "estate catalog identity or routing changed",
                        }
                    )
                else:
                    results.append(
                        {"estate": catalog.id, **self._status_receipt(receipt)}
                    )
        for receipt_path, receipt in self._receipts_for_socket(context.socket_path):
            if receipt_path in seen_receipts:
                continue
            status = self._status_receipt(receipt)
            results.append(
                {
                    "estate": receipt.get("estate"),
                    **status,
                    "ok": False,
                    "state": "source-missing",
                    "error": "managed estate catalog source is unavailable",
                }
            )
        for root in missing_roots:
            results.append(
                {
                    "estate": str(root),
                    "ok": False,
                    "state": "source-missing",
                    "managed": False,
                    "error": "configured estate catalog root is unavailable",
                }
            )
        return {
            "ok": all(result.get("ok") for result in results),
            "estates": results,
        }

    def down(self, roots: Iterable[str | Path]) -> dict[str, Any]:
        context = self.client.context()
        catalogs = discover_catalogs(
            [
                root
                for root in roots
                if Path(root).expanduser().resolve().is_dir()
            ]
        )
        receipts = list(self._receipts_for_socket(context.socket_path))
        receipt_paths = {path for path, _receipt in receipts}
        results = []
        for receipt_path, receipt in reversed(receipts):
            with self.receipts.operation_lock(receipt_path):
                current = self.receipts.load(
                    receipt_path,
                    schema=CATALOG_RECEIPT_SCHEMA,
                )
                if current is not None:
                    results.append(self._close_receipt(receipt_path, current))
        for catalog in catalogs:
            path = self._path(catalog, context.socket_path)
            if path not in receipt_paths:
                results.append(
                    {"estate": catalog.id, "ok": True, "state": "down"}
                )
        return {
            "ok": all(result.get("ok") for result in results),
            "estates": list(reversed(results)),
        }
