from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .catalog import CatalogManager, discover_catalogs
from .herdr import HerdrClient
from .manager import NeighborhoodManager, _powershell_command
from .model import RappHerdrError, load_neighborhood, resolve_topology
from .receipts import ReceiptStore

ESTATE_SCHEMA = "rapp-herdr-estate/1.0"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{field} must be a non-empty string")
    if "\0" in value or "\n" in value or "\r" in value:
        raise RappHerdrError(f"{field} contains an unsafe control character")
    return value.strip()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid estate manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"estate manifest must contain an object: {path}")
    return value


@dataclass(frozen=True)
class EstateNeighborhood:
    manifest: str
    members: str | None
    estate_roots: tuple[str, ...]
    base_port: int
    brainstem_python: str | None
    bootstrap: bool
    listen_host: str
    entrypoint: str

    def payload(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest,
            "members": self.members,
            "estate_roots": list(self.estate_roots),
            "base_port": self.base_port,
            "brainstem_python": self.brainstem_python,
            "bootstrap": self.bootstrap,
            "listen_host": self.listen_host,
            "entrypoint": self.entrypoint,
        }


@dataclass(frozen=True)
class EstateDevice:
    id: str
    enabled: bool
    transport: str
    os: str
    ssh: str | None
    session: str
    herdr_bin: str
    rapp_herdr_bin: str
    receipt_root: str | None
    inventory_roots: tuple[str, ...]
    catalog_roots: tuple[str, ...]
    neighborhoods: tuple[EstateNeighborhood, ...]
    note: str | None

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session": self.session,
            "herdr_bin": self.herdr_bin,
            "receipt_root": self.receipt_root,
            "inventory_roots": list(self.inventory_roots),
            "catalog_roots": list(self.catalog_roots),
            "neighborhoods": [
                neighborhood.payload() for neighborhood in self.neighborhoods
            ],
        }


@dataclass(frozen=True)
class Estate:
    name: str
    manifest_path: Path
    devices: tuple[EstateDevice, ...]


def load_estate(path: str | Path) -> Estate:
    manifest_path = Path(path).expanduser().resolve()
    value = _load_json(manifest_path)
    if value.get("schema") != ESTATE_SCHEMA:
        raise RappHerdrError(
            f"{manifest_path}: expected schema {ESTATE_SCHEMA!r}"
        )
    name = _required_text(value.get("name"), "estate.name")
    raw_devices = value.get("devices")
    if not isinstance(raw_devices, list) or not raw_devices:
        raise RappHerdrError("estate.devices must be a non-empty array")
    devices: list[EstateDevice] = []
    seen_ids: set[str] = set()
    local_count = 0
    for index, raw in enumerate(raw_devices):
        if not isinstance(raw, dict):
            raise RappHerdrError(f"estate.devices[{index}] must be an object")
        device_id = _required_text(raw.get("id"), f"estate.devices[{index}].id")
        if not _SAFE_ID.fullmatch(device_id):
            raise RappHerdrError(f"unsafe estate device id: {device_id!r}")
        if device_id in seen_ids:
            raise RappHerdrError(f"duplicate estate device id: {device_id!r}")
        seen_ids.add(device_id)
        transport = _required_text(
            raw.get("transport", "local"),
            f"estate.devices[{index}].transport",
        )
        if transport not in {"local", "ssh"}:
            raise RappHerdrError(
                f"estate.devices[{index}].transport must be local or ssh"
            )
        if transport == "local":
            local_count += 1
        device_os = _required_text(
            raw.get("os", "posix"),
            f"estate.devices[{index}].os",
        )
        if device_os not in {"posix", "windows"}:
            raise RappHerdrError(
                f"estate.devices[{index}].os must be posix or windows"
            )
        ssh_alias = raw.get("ssh")
        if transport == "ssh":
            ssh_alias = _required_text(
                ssh_alias,
                f"estate.devices[{index}].ssh",
            )
            if not _SAFE_ID.fullmatch(ssh_alias) or ssh_alias.startswith("-"):
                raise RappHerdrError(f"unsafe SSH alias: {ssh_alias!r}")
        elif ssh_alias is not None:
            raise RappHerdrError("local estate devices cannot declare ssh")
        session = _required_text(
            raw.get("session", "rapp-estate"),
            f"estate.devices[{index}].session",
        )
        if not _SAFE_ID.fullmatch(session):
            raise RappHerdrError(f"unsafe Herdr session name: {session!r}")
        raw_neighborhoods = raw.get("neighborhoods", [])
        if not isinstance(raw_neighborhoods, list):
            raise RappHerdrError(
                f"estate.devices[{index}].neighborhoods must be an array"
            )
        neighborhoods: list[EstateNeighborhood] = []
        for neighborhood_index, neighborhood in enumerate(raw_neighborhoods):
            if not isinstance(neighborhood, dict):
                raise RappHerdrError(
                    f"estate.devices[{index}].neighborhoods"
                    f"[{neighborhood_index}] must be an object"
                )
            roots = neighborhood.get("estate_roots", ["~/.rapp/twins"])
            if not isinstance(roots, list) or not roots:
                raise RappHerdrError("estate_roots must be a non-empty array")
            base_port = neighborhood.get("base_port", 7081)
            if not isinstance(base_port, int) or not 1 <= base_port <= 65535:
                raise RappHerdrError("base_port must be an integer from 1 to 65535")
            neighborhoods.append(
                EstateNeighborhood(
                    manifest=_required_text(
                        neighborhood.get("manifest"),
                        "neighborhood.manifest",
                    ),
                    members=(
                        _required_text(neighborhood.get("members"), "neighborhood.members")
                        if neighborhood.get("members") is not None
                        else None
                    ),
                    estate_roots=tuple(
                        _required_text(root, "neighborhood.estate_roots[]")
                        for root in roots
                    ),
                    base_port=base_port,
                    brainstem_python=(
                        _required_text(
                            neighborhood.get("brainstem_python"),
                            "neighborhood.brainstem_python",
                        )
                        if neighborhood.get("brainstem_python") is not None
                        else None
                    ),
                    bootstrap=bool(neighborhood.get("bootstrap", True)),
                    listen_host=_required_text(
                        neighborhood.get("listen_host", "127.0.0.1"),
                        "neighborhood.listen_host",
                    ),
                    entrypoint=_required_text(
                        neighborhood.get("entrypoint", "brainstem.py"),
                        "neighborhood.entrypoint",
                    ),
                )
            )
        devices.append(
            EstateDevice(
                id=device_id,
                enabled=bool(raw.get("enabled", True)),
                transport=transport,
                os=device_os,
                ssh=ssh_alias,
                session=session,
                herdr_bin=_required_text(
                    raw.get("herdr_bin", "herdr"),
                    f"estate.devices[{index}].herdr_bin",
                ),
                rapp_herdr_bin=_required_text(
                    raw.get("rapp_herdr_bin", "rapp-herdr"),
                    f"estate.devices[{index}].rapp_herdr_bin",
                ),
                receipt_root=(
                    _required_text(
                        raw.get("receipt_root"),
                        f"estate.devices[{index}].receipt_root",
                    )
                    if raw.get("receipt_root") is not None
                    else None
                ),
                inventory_roots=tuple(
                    _required_text(root, f"estate.devices[{index}].inventory_roots[]")
                    for root in raw.get("inventory_roots", ["~/.rapp/twins"])
                ),
                catalog_roots=tuple(
                    _required_text(root, f"estate.devices[{index}].catalog_roots[]")
                    for root in raw.get("catalog_roots", [])
                ),
                neighborhoods=tuple(neighborhoods),
                note=(
                    _required_text(raw.get("note"), f"estate.devices[{index}].note")
                    if raw.get("note") is not None
                    else None
                ),
            )
        )
    if local_count > 1:
        raise RappHerdrError("an estate can declare at most one local device")
    return Estate(name=name, manifest_path=manifest_path, devices=tuple(devices))


def _start_herdr_session(binary: str, session: str) -> HerdrClient:
    client = HerdrClient(binary=binary, session=session)
    try:
        client.context()
        return client
    except RappHerdrError:
        pass
    command = [client.binary, "--session", session, "server"]
    if os.name == "nt":
        task_command = _windows_herdr_task_command(client.binary, session)
        result = subprocess.run(
            task_command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RappHerdrError(
                f"cannot register persistent Herdr task: {detail}"
            )
    else:
        try:
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            raise RappHerdrError(
                f"cannot start Herdr session {session!r}: {exc}"
            ) from exc
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            client.context()
            return client
        except RappHerdrError:
            time.sleep(0.1)
    raise RappHerdrError(f"Herdr session {session!r} did not become ready")


def _windows_herdr_task_command(binary: str, session: str) -> list[str]:
    payload = base64.b64encode(
        json.dumps(
            {
                "binary": binary,
                "session": session,
                "task": f"RAPP-Herdr-{session}",
            },
            separators=(",", ":"),
        ).encode()
    ).decode("ascii")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}'));"
        "$p=$json|ConvertFrom-Json;"
        "$args='--session '+[string]$p.session+' server';"
        "$action=New-ScheduledTaskAction -Execute ([string]$p.binary) -Argument $args;"
        "$trigger=New-ScheduledTaskTrigger -AtLogOn;"
        "Register-ScheduledTask -TaskName ([string]$p.task) -Action $action "
        "-Trigger $trigger -Description 'Persistent RAPP-Herdr estate session' "
        "-Force|Out-Null;"
        "Start-ScheduledTask -TaskName ([string]$p.task)"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded,
    ]


def _inventory_twins(
    roots: list[str],
    assigned_rappids: set[str],
) -> dict[str, Any]:
    twins: list[dict[str, Any]] = []
    other_organisms: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    seen_workspaces: set[Path] = set()
    for raw_root in roots:
        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            continue
        candidates = [root] if (root / "rappid.json").is_file() else sorted(root.iterdir())
        for candidate in candidates:
            workspace = candidate.resolve()
            if (
                workspace in seen_workspaces
                or not workspace.is_dir()
                or not (workspace / "rappid.json").is_file()
            ):
                continue
            if workspace != root and root not in workspace.parents:
                continue
            seen_workspaces.add(workspace)
            try:
                identity = json.loads(
                    (workspace / "rappid.json").read_text(encoding="utf-8")
                )
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                invalid.append(
                    {
                        "workspace": str(workspace),
                        "assigned": False,
                        "runnable": False,
                        "error": str(exc),
                    }
                )
                continue
            if not isinstance(identity, dict):
                continue
            rappid = identity.get("rappid")
            kind = identity.get("kind")
            item = {
                "workspace": str(workspace),
                "rappid": rappid,
                "name": identity.get("display_name") or identity.get("name"),
                "kind": kind,
                "assigned": isinstance(rappid, str) and rappid in assigned_rappids,
                "runnable": (
                    (workspace / "brainstem.py").is_file()
                    or (workspace / "serve.py").is_file()
                ),
                "entrypoints": [
                    entrypoint
                    for entrypoint in ("brainstem.py", "serve.py")
                    if (workspace / entrypoint).is_file()
                ],
            }
            if isinstance(rappid, str) and rappid and str(kind).casefold() == "twin":
                twins.append(item)
            else:
                other_organisms.append(item)
    return {
        "total": len(twins),
        "assigned": sum(1 for twin in twins if twin.get("assigned")),
        "unassigned": sum(1 for twin in twins if not twin.get("assigned")),
        "runnable": sum(1 for twin in twins if twin.get("runnable")),
        "twins": twins,
        "other_organisms": other_organisms,
        "other_organism_count": len(other_organisms),
        "invalid": invalid,
    }


def _neighborhood_ownership_ok(result: dict[str, Any]) -> bool:
    state = result.get("state")
    return state == "down" or bool(result.get("managed"))


def run_estate_device(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    if action not in {"up", "status", "down"}:
        raise RappHerdrError(f"unsupported estate device action: {action}")
    device_id = _required_text(payload.get("id"), "device.id")
    session = _required_text(payload.get("session"), "device.session")
    herdr_bin = str(Path(_required_text(payload.get("herdr_bin"), "device.herdr_bin")).expanduser())
    if action == "up":
        client = _start_herdr_session(herdr_bin, session)
        session_state = "running"
    else:
        try:
            client = HerdrClient(binary=herdr_bin, session=session)
            client.context()
            session_state = "running"
        except RappHerdrError:
            client = None
            session_state = "stopped"
    receipt_store = ReceiptStore(payload.get("receipt_root"))
    manager = NeighborhoodManager(client, receipt_store) if client else None
    neighborhoods = payload.get("neighborhoods", [])
    if not isinstance(neighborhoods, list):
        raise RappHerdrError("device.neighborhoods must be an array")
    results: list[dict[str, Any]] = []
    assigned_rappids: set[str] = set()
    ordered = list(reversed(neighborhoods)) if action == "down" else neighborhoods
    for raw in ordered:
        if not isinstance(raw, dict):
            raise RappHerdrError("device neighborhood must be an object")
        manifest = str(Path(_required_text(raw.get("manifest"), "manifest")).expanduser())
        members = raw.get("members")
        neighborhood = load_neighborhood(
            manifest,
            str(Path(members).expanduser()) if isinstance(members, str) else None,
        )
        assigned_rappids.update(neighborhood.member_rappids)
        try:
            if manager is None:
                result = {
                    "state": "down",
                    "managed": False,
                    "reason": "Herdr session is stopped",
                }
            elif action == "up":
                topology = resolve_topology(
                    neighborhood,
                    [
                        str(Path(root).expanduser())
                        for root in raw.get("estate_roots", ["~/.rapp/twins"])
                    ],
                    require_all_local=True,
                )
                result = manager.up(
                    topology,
                    base_port=int(raw.get("base_port", 7081)),
                    brainstem_python=raw.get("brainstem_python"),
                    bootstrap=bool(raw.get("bootstrap", True)),
                    listen_host=str(raw.get("listen_host", "127.0.0.1")),
                    entrypoint=str(raw.get("entrypoint", "brainstem.py")),
                )
            elif action == "status":
                result = manager.status(neighborhood)
            else:
                result = manager.down(neighborhood)
            results.append(
                {
                    "manifest": manifest,
                    "ok": _neighborhood_ownership_ok(result),
                    "result": result,
                }
            )
        except RappHerdrError as exc:
            results.append(
                {
                    "manifest": manifest,
                    "ok": False,
                    "error": str(exc),
                }
            )
    catalog_roots = [
        str(Path(root).expanduser())
        for root in payload.get("catalog_roots", [])
    ]
    if not catalog_roots:
        catalog_result = {"ok": True, "estates": []}
    elif client is None:
        catalog_result = {
            "ok": True,
            "state": "stopped",
            "estates": [
                {
                    "estate": catalog.id,
                    "state": "down",
                    "cells": len(catalog.cells),
                }
                for catalog in discover_catalogs(catalog_roots)
            ],
        }
    else:
        catalog_manager = CatalogManager(client, receipt_store)
        catalog_result = getattr(catalog_manager, action)(catalog_roots)
    return {
        "ok": all(result["ok"] for result in results)
        and bool(catalog_result.get("ok")),
        "device": device_id,
        "session": session_state,
        "neighborhoods": results,
        "catalogs": catalog_result,
        "inventory": _inventory_twins(
            [
                str(Path(root).expanduser())
                for root in payload.get("inventory_roots", ["~/.rapp/twins"])
            ],
            assigned_rappids,
        ),
    }


def encode_device_payload(device: EstateDevice) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(device.payload(), separators=(",", ":")).encode()
    ).decode()


def decode_device_payload(encoded: str) -> dict[str, Any]:
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded).decode())
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid encoded estate device payload: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError("estate device payload must contain an object")
    return value


class EstateManager:
    def __init__(
        self,
        estate: Estate,
        *,
        ssh_binary: str | None = None,
        timeout: float = 360.0,
    ):
        self.estate = estate
        self.ssh_binary = ssh_binary or shutil.which("ssh")
        self.timeout = timeout

    def plan(self) -> dict[str, Any]:
        return {
            "ok": True,
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "devices": [
                {
                    "id": device.id,
                    "enabled": device.enabled,
                    "transport": device.transport,
                    "ssh": device.ssh,
                    "os": device.os,
                    "session": device.session,
                    "inventory_roots": list(device.inventory_roots),
                    "receipt_root": device.receipt_root,
                    "catalog_roots": list(device.catalog_roots),
                    "neighborhoods": [
                        neighborhood.payload()
                        for neighborhood in device.neighborhoods
                    ],
                    "note": device.note,
                }
                for device in self.estate.devices
            ],
        }

    def _run_remote(self, device: EstateDevice, action: str) -> dict[str, Any]:
        if not self.ssh_binary:
            return {
                "ok": False,
                "device": device.id,
                "reachable": False,
                "error": "ssh is not installed",
            }
        arguments = [
            device.rapp_herdr_bin,
            "_estate-device",
            action,
            "--payload",
            encode_device_payload(device),
        ]
        command = (
            _powershell_command(arguments)
            if device.os == "windows"
            else shlex.join(arguments)
        )
        result = subprocess.run(
            [
                self.ssh_binary,
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                device.ssh or "",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "ok": False,
                "device": device.id,
                "reachable": result.returncode != 255,
                "error": f"remote returned non-JSON output: {result.stdout.strip()}",
            }
        if not isinstance(value, dict):
            return {
                "ok": False,
                "device": device.id,
                "reachable": True,
                "error": "remote returned an invalid result",
            }
        value["reachable"] = True
        if result.returncode != 0 and "ok" not in value:
            value["ok"] = False
            value["error"] = (
                value.get("error")
                or (result.stderr or "").strip()
                or f"remote exited {result.returncode}"
            )
        return value

    @staticmethod
    def _run_local(device: EstateDevice, action: str) -> dict[str, Any]:
        value = run_estate_device(action, device.payload())
        value["reachable"] = True
        return value

    def run(self, action: str) -> dict[str, Any]:
        if action == "plan":
            return self.plan()
        results_by_id: dict[str, dict[str, Any]] = {}
        enabled = [device for device in self.estate.devices if device.enabled]
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(enabled)))) as executor:
            futures = {
                executor.submit(
                    self._run_local if device.transport == "local" else self._run_remote,
                    device,
                    action,
                ): device
                for device in enabled
            }
            for future in as_completed(futures):
                device = futures[future]
                try:
                    results_by_id[device.id] = future.result()
                except (OSError, subprocess.TimeoutExpired, RappHerdrError) as exc:
                    results_by_id[device.id] = {
                        "ok": False,
                        "device": device.id,
                        "reachable": False,
                        "error": str(exc),
                    }
        results = []
        for device in self.estate.devices:
            if not device.enabled:
                results.append(
                    {
                        "ok": True,
                        "device": device.id,
                        "reachable": False,
                        "skipped": True,
                        "note": device.note,
                    }
                )
            else:
                results.append(results_by_id[device.id])
        return {
            "ok": all(result.get("ok") for result in results),
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "action": action,
            "devices": results,
        }
