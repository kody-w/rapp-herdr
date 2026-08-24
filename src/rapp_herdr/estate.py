from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .audit import audit_machine
from .buddy import (
    BUDDY_SCHEMA,
    add_buddy_neighborhood,
    buddy_chat_payload,
    buddy_cleanup_payload,
    buddy_handshake_payload,
    buddy_payload,
    encode_buddy_payload,
    run_buddy_device,
)
from .catalog import CatalogManager, discover_catalogs
from .herdr import HerdrClient
from .manager import NeighborhoodManager, _powershell_command
from .model import RappHerdrError, load_neighborhood, resolve_topology
from .probe import (
    PROBE_NEIGHBORHOOD_MANIFEST,
    PROBE_SCHEMA,
    add_probe_neighborhoods,
    encode_probe_payload,
    probe_brainstem_python,
    probe_payload,
    probe_rappid,
    run_probe_device,
)
from .receipts import ReceiptStore

ESTATE_SCHEMA = "rapp-herdr-estate/1.0"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_RAPP_OWNER = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_LOOPBACK_URL = re.compile(
    r"^http://(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})/?$"
)


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{field} must be a non-empty string")
    if "\0" in value or "\n" in value or "\r" in value:
        raise RappHerdrError(f"{field} contains an unsafe control character")
    return value.strip()


def _manifest_identity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("\\", "/")
    marker = "/.rapp/"
    if marker in normalized:
        return normalized[normalized.index(marker) + 1:]
    if normalized.startswith("~/.rapp/"):
        return normalized[2:]
    return normalized


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid estate manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"estate manifest must contain an object: {path}")
    return value


def _string_array(
    value: Any,
    field: str,
    *,
    require_nonempty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RappHerdrError(f"{field} must be an array")
    items = tuple(
        _required_text(item, f"{field}[]")
        for item in value
    )
    if require_nonempty and not items:
        raise RappHerdrError(f"{field} must contain at least one path")
    return items


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
    managed_by: str | None = None
    buddy_name: str | None = None
    buddy_rappid: str | None = None
    buddy_ui: str | None = None

    def payload(self) -> dict[str, Any]:
        value = {
            "manifest": self.manifest,
            "members": self.members,
            "estate_roots": list(self.estate_roots),
            "base_port": self.base_port,
            "brainstem_python": self.brainstem_python,
            "bootstrap": self.bootstrap,
            "listen_host": self.listen_host,
            "entrypoint": self.entrypoint,
        }
        if self.managed_by is not None:
            value["managed_by"] = self.managed_by
        if self.buddy_name is not None:
            value["buddy"] = {
                "name": self.buddy_name,
                "rappid": self.buddy_rappid,
                "ui": self.buddy_ui,
            }
        return value


@dataclass(frozen=True)
class EstateProbeTarget:
    name: str
    url: str
    rappid: str | None

    def payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "rappid": self.rappid,
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
    audit_roots: tuple[str, ...]
    neighborhoods: tuple[EstateNeighborhood, ...]
    probe_target: EstateProbeTarget | None
    note: str | None

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session": self.session,
            "herdr_bin": self.herdr_bin,
            "receipt_root": self.receipt_root,
            "inventory_roots": list(self.inventory_roots),
            "catalog_roots": list(self.catalog_roots),
            "audit_roots": list(self.audit_roots),
            "neighborhoods": [
                neighborhood.payload() for neighborhood in self.neighborhoods
            ],
            "probe_target": (
                self.probe_target.payload() if self.probe_target else None
            ),
        }


@dataclass(frozen=True)
class Estate:
    name: str
    buddy_owner: str | None
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
    raw_buddy_owner = value.get("buddy_owner")
    buddy_owner = (
        _required_text(raw_buddy_owner, "estate.buddy_owner")
        if raw_buddy_owner is not None
        else None
    )
    if buddy_owner is not None and (
        len(buddy_owner) > 39 or not _RAPP_OWNER.fullmatch(buddy_owner)
    ):
        raise RappHerdrError("estate.buddy_owner is not a canonical RAPP/1 owner")
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
            raw_buddy = neighborhood.get("buddy")
            if raw_buddy is not None and not isinstance(raw_buddy, dict):
                raise RappHerdrError("neighborhood.buddy must be an object")
            if raw_buddy is not None and (
                not isinstance(raw_buddy.get("ui"), str)
                or raw_buddy.get("ui") not in {"chat", "rapplication"}
            ):
                raise RappHerdrError(
                    "neighborhood.buddy.ui must be chat or rapplication"
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
                    managed_by=(
                        _required_text(
                            neighborhood.get("managed_by"),
                            "neighborhood.managed_by",
                        )
                        if neighborhood.get("managed_by") is not None
                        else None
                    ),
                    buddy_name=(
                        _required_text(
                            raw_buddy.get("name"),
                            "neighborhood.buddy.name",
                        )
                        if raw_buddy is not None
                        else None
                    ),
                    buddy_rappid=(
                        _required_text(
                            raw_buddy.get("rappid"),
                            "neighborhood.buddy.rappid",
                        )
                        if raw_buddy is not None
                        and raw_buddy.get("rappid") is not None
                        else None
                    ),
                    buddy_ui=(
                        _required_text(
                            raw_buddy.get("ui"),
                            "neighborhood.buddy.ui",
                        )
                        if raw_buddy is not None
                        and raw_buddy.get("ui") is not None
                        else None
                    ),
                )
            )
        probe_target = None
        raw_probe_target = raw.get("probe_target")
        if raw_probe_target is not None:
            if not isinstance(raw_probe_target, dict):
                raise RappHerdrError(
                    f"estate.devices[{index}].probe_target must be an object"
                )
            target_url = _required_text(
                raw_probe_target.get("url"),
                f"estate.devices[{index}].probe_target.url",
            )
            target_match = _LOOPBACK_URL.fullmatch(target_url)
            if not target_match or not 1 <= int(target_match.group(1)) <= 65535:
                raise RappHerdrError(
                    f"estate.devices[{index}].probe_target.url must be a "
                    "loopback HTTP URL with an explicit port"
                )
            probe_target = EstateProbeTarget(
                name=_required_text(
                    raw_probe_target.get("name"),
                    f"estate.devices[{index}].probe_target.name",
                ),
                url=target_url.rstrip("/"),
                rappid=(
                    _required_text(
                        raw_probe_target.get("rappid"),
                        f"estate.devices[{index}].probe_target.rappid",
                    )
                    if raw_probe_target.get("rappid") is not None
                    else None
                ),
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
                inventory_roots=_string_array(
                    raw.get("inventory_roots", ["~/.rapp/twins"]),
                    f"estate.devices[{index}].inventory_roots",
                    require_nonempty=True,
                ),
                catalog_roots=_string_array(
                    raw.get("catalog_roots", []),
                    f"estate.devices[{index}].catalog_roots",
                ),
                audit_roots=_string_array(
                    raw.get("audit_roots", []),
                    f"estate.devices[{index}].audit_roots",
                ),
                neighborhoods=tuple(neighborhoods),
                probe_target=probe_target,
                note=(
                    _required_text(raw.get("note"), f"estate.devices[{index}].note")
                    if raw.get("note") is not None
                    else None
                ),
            )
        )
    if local_count > 1:
        raise RappHerdrError("an estate can declare at most one local device")
    return Estate(
        name=name,
        buddy_owner=buddy_owner,
        manifest_path=manifest_path,
        devices=tuple(devices),
    )


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
    if action not in {"up", "status", "down", "audit"}:
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
            if action == "audit":
                result = {
                    "state": "observed",
                    "managed": False,
                }
            elif manager is None:
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
                    "ok": (
                        True
                        if action == "audit"
                        else _neighborhood_ownership_ok(result)
                    ),
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
    if action == "audit":
        catalog_result = {
            "ok": True,
            "estates": [
                {
                    "estate": catalog.id,
                    "state": "observed",
                    "cells": [
                        {
                            "id": cell.id,
                            "label": cell.label,
                            "pane_id": None,
                            "agent_status": "observed",
                            "managed": False,
                            "live": False,
                        }
                        for cell in catalog.cells
                    ],
                }
                for catalog in discover_catalogs(
                    [
                        root for root in catalog_roots
                        if Path(root).expanduser().is_dir()
                    ]
                )
            ],
        }
    elif not catalog_roots:
        catalog_result = {"ok": True, "estates": []}
    elif client is None:
        catalog_result = {
            "ok": True,
            "state": "stopped",
            "estates": [
                {
                    "estate": catalog.id,
                    "state": "down",
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
                for catalog in discover_catalogs(catalog_roots)
            ],
        }
    else:
        catalog_manager = CatalogManager(client, receipt_store)
        catalog_result = getattr(catalog_manager, action)(catalog_roots)
    try:
        audit = audit_machine(payload, assigned_rappids=assigned_rappids)
    except Exception as exc:
        audit = {
            "schema": "rapp-herdr-audit/1.0",
            "ok": False,
            "error": str(exc),
            "assets": [],
            "asset_count": 0,
            "services": [],
            "service_count": 0,
            "jobs": [],
            "findings": [
                {
                    "severity": "error",
                    "kind": "audit-failed",
                    "message": str(exc),
                }
            ],
        }
    lifecycle_ok = all(result["ok"] for result in results) and bool(
        catalog_result.get("ok")
    )
    return {
        "ok": lifecycle_ok and (
            bool(audit.get("ok")) if action == "audit" else True
        ),
        "device": device_id,
        "session": session_state,
        "neighborhoods": results,
        "catalogs": catalog_result,
        "audit": audit,
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
        self.controller_receipts = ReceiptStore()

    def plan(self) -> dict[str, Any]:
        return {
            "ok": True,
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "buddy_owner": self.estate.buddy_owner,
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
                    "audit_roots": list(device.audit_roots),
                    "neighborhoods": [
                        neighborhood.payload()
                        for neighborhood in device.neighborhoods
                    ],
                    "probe_target": (
                        device.probe_target.payload()
                        if device.probe_target
                        else None
                    ),
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
        try:
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
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "device": device.id,
                "reachable": True,
                "indeterminate": True,
                "error": "remote estate lifecycle timed out",
            }
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

    def _run_remote_probe(
        self,
        device: EstateDevice,
        action: str,
        *,
        base_port: int,
        message: str | None,
    ) -> dict[str, Any]:
        if not self.ssh_binary:
            return {
                "ok": False,
                "device": device.id,
                "reachable": False,
                "error": "ssh is not installed",
            }
        arguments = [
            device.rapp_herdr_bin,
            "_probe-device",
            action,
            "--payload",
            encode_probe_payload(
                probe_payload(
                    device.id,
                    device.inventory_roots[0],
                    base_port=base_port,
                    message=message,
                    relay_target=(
                        device.probe_target.payload()
                        if device.probe_target
                        else None
                    ),
                )
            ),
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
                "error": "remote returned an invalid probe result",
            }
        value["reachable"] = True
        return value

    def _run_remote_buddy(
        self,
        device: EstateDevice,
        action: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if not self.ssh_binary:
            return {
                "ok": False,
                "device": device.id,
                "reachable": False,
                "error": "ssh is not installed",
            }
        arguments = [
            device.rapp_herdr_bin,
            "_buddy-device",
            action,
            "--payload-stdin",
        ]
        command = (
            _powershell_command(arguments)
            if device.os == "windows"
            else shlex.join(arguments)
        )
        try:
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
                input=encode_buddy_payload(payload),
                timeout=max(self.timeout, 240),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "device": device.id,
                "reachable": True,
                "indeterminate": True,
                "error": "remote buddy operation timed out",
            }
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "ok": False,
                "device": device.id,
                "reachable": result.returncode != 255,
                "error": "remote buddy operation returned non-JSON output",
            }
        if not isinstance(value, dict):
            return {
                "ok": False,
                "device": device.id,
                "reachable": True,
                "error": "remote buddy operation returned an invalid result",
            }
        value["reachable"] = True
        return value

    @staticmethod
    def _run_local_buddy(
        device: EstateDevice,
        action: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        value = run_buddy_device(action, payload)
        value["reachable"] = True
        return value

    @staticmethod
    def _run_local_probe(
        device: EstateDevice,
        action: str,
        *,
        base_port: int,
        message: str | None,
    ) -> dict[str, Any]:
        value = run_probe_device(
            action,
            probe_payload(
                device.id,
                device.inventory_roots[0],
                base_port=base_port,
                message=message,
                relay_target=(
                    device.probe_target.payload()
                    if device.probe_target
                    else None
                ),
            ),
        )
        value["reachable"] = True
        return value

    @staticmethod
    def _probe_runtime_device(
        device: EstateDevice,
        *,
        base_port: int,
    ) -> EstateDevice:
        return replace(
            device,
            catalog_roots=(),
            audit_roots=(),
            neighborhoods=(
                EstateNeighborhood(
                    manifest=PROBE_NEIGHBORHOOD_MANIFEST,
                    members=None,
                    estate_roots=(device.inventory_roots[0],),
                    base_port=base_port,
                    brainstem_python=probe_brainstem_python(device.os),
                    bootstrap=False,
                    listen_host="127.0.0.1",
                    entrypoint="brainstem.py",
                ),
            ),
        )

    def _run_probe_runtime(
        self,
        device: EstateDevice,
        action: str,
        *,
        base_port: int,
    ) -> dict[str, Any]:
        probe_device = self._probe_runtime_device(
            device,
            base_port=base_port,
        )
        runner = (
            self._run_local
            if device.transport == "local"
            else self._run_remote
        )
        if action != "restart":
            return runner(
                probe_device,
                "up" if action == "start" else "down",
            )
        stopped = runner(probe_device, "down")
        if not stopped.get("ok"):
            return {
                **stopped,
                "restart": {"stopped": stopped, "started": None},
            }
        started = runner(probe_device, "up")
        return {
            **started,
            "restart": {"stopped": stopped, "started": started},
        }

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

    def probe(self, action: str, *, base_port: int = 7199) -> dict[str, Any]:
        if action not in {
            "seed",
            "start",
            "stop",
            "restart",
            "mark",
            "verify",
        }:
            raise RappHerdrError(f"unsupported persistence probe action: {action}")
        if not 1 <= base_port <= 65535:
            raise RappHerdrError("probe base port must be from 1 to 65535")
        message = (
            f"persistence-{action}-"
            + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            if action in {"mark", "verify"}
            else None
        )
        results_by_id: dict[str, dict[str, Any]] = {}
        enabled = [device for device in self.estate.devices if device.enabled]
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(enabled)))) as executor:
            futures = {
                executor.submit(
                    (
                        (
                            self._run_local_probe
                            if device.transport == "local"
                            else self._run_remote_probe
                        )
                        if action in {"seed", "mark", "verify"}
                        else self._run_probe_runtime
                    ),
                    device,
                    action,
                    base_port=base_port,
                    **(
                        {"message": message}
                        if action in {"seed", "mark", "verify"}
                        else {}
                    ),
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
        results = [
            (
                {
                    "ok": True,
                    "device": device.id,
                    "reachable": False,
                    "skipped": True,
                    "note": device.note,
                }
                if not device.enabled
                else results_by_id[device.id]
            )
            for device in self.estate.devices
        ]
        manifest_update = None
        if action == "seed":
            seeded_ids = {
                str(result["device"])
                for result in results
                if result.get("ok") and not result.get("skipped")
            }
            manifest_update = add_probe_neighborhoods(
                self.estate.manifest_path,
                seeded_ids,
                base_port=base_port,
            )
        return {
            "ok": all(result.get("ok") for result in results),
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "action": f"probe-{action}",
            "message": message,
            "manifest_update": manifest_update,
            "devices": results,
        }

    def create_buddy(
        self,
        *,
        device_id: str,
        name: str,
        role: str,
        ui: str = "auto",
        port_start: int = 7200,
    ) -> dict[str, Any]:
        lock_digest = hashlib.sha256(
            str(self.estate.manifest_path).encode()
        ).hexdigest()[:32]
        lock_path = (
            self.controller_receipts.root
            / "estate-buddies"
            / f"{lock_digest}.json"
        )
        with self.controller_receipts.operation_lock(
            lock_path,
            wait_timeout=5,
        ):
            return self._create_buddy_locked(
                device_id=device_id,
                name=name,
                role=role,
                ui=ui,
                port_start=port_start,
            )

    def _create_buddy_locked(
        self,
        *,
        device_id: str,
        name: str,
        role: str,
        ui: str,
        port_start: int,
    ) -> dict[str, Any]:
        device_id = _required_text(device_id, "buddy.device_id")
        name = _required_text(name, "buddy.name")
        if len(name) > 80:
            raise RappHerdrError("buddy.name must be at most 80 characters")
        if not isinstance(role, str) or not role.strip():
            raise RappHerdrError("buddy.role must be a non-empty string")
        role = role.strip()
        if len(role) > 4_000 or "\0" in role or "\r" in role:
            raise RappHerdrError("buddy.role is invalid")
        if (
            not isinstance(ui, str)
            or ui not in {"auto", "chat", "rapplication"}
        ):
            raise RappHerdrError(
                "buddy.ui must be auto, chat, or rapplication"
            )
        if (
            isinstance(port_start, bool)
            or not isinstance(port_start, int)
            or not 7200 <= port_start <= 7299
        ):
            raise RappHerdrError(
                "buddy.port_start must be an integer from 7200 to 7299"
            )
        matches = [
            device
            for device in self.estate.devices
            if device.id == device_id and device.enabled
        ]
        if len(matches) != 1:
            raise RappHerdrError(
                f"enabled estate device {device_id!r} is not unique"
            )
        device = matches[0]
        owner = self.estate.buddy_owner
        if owner is None:
            raise RappHerdrError(
                "estate.buddy_owner is required to mint a buddy"
            )
        payload = buddy_payload(
            device.id,
            device.inventory_roots[0],
            owner=owner,
            name=name,
            role=role,
            ui=ui,
            port_start=port_start,
        )
        runner = (
            self._run_local_buddy
            if device.transport == "local"
            else self._run_remote_buddy
        )
        initial_manifest_hash = hashlib.sha256(
            self.estate.manifest_path.read_bytes()
        ).hexdigest()
        created = runner(device, "create", payload)
        if not created.get("ok"):
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
            }
        if hashlib.sha256(
            self.estate.manifest_path.read_bytes()
        ).hexdigest() != initial_manifest_hash:
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=None,
                updated_device=None,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "error": "estate manifest changed during buddy creation",
                "rollback": rollback,
            }
        try:
            registered = add_buddy_neighborhood(
                self.estate.manifest_path,
                device.id,
                created["neighborhood"],
                expected_hash=initial_manifest_hash,
            )
        except (OSError, RappHerdrError) as exc:
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=None,
                updated_device=None,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "error": f"buddy registration failed: {exc}",
                "rollback": rollback,
            }
        try:
            updated_estate = load_estate(self.estate.manifest_path)
        except RappHerdrError as exc:
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=registered,
                updated_device=None,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "registered": registered,
                "error": f"registered buddy manifest is invalid: {exc}",
                "rollback": rollback,
            }
        updated_device = next(
            current for current in updated_estate.devices
            if current.id == device.id
        )
        matching_neighborhoods = tuple(
            neighborhood
            for neighborhood in updated_device.neighborhoods
            if neighborhood.manifest == created["neighborhood"]["manifest"]
        )
        if len(matching_neighborhoods) != 1:
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=registered,
                updated_device=None,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "registered": registered,
                "error": "registered buddy neighborhood could not be isolated",
                "rollback": rollback,
            }
        isolated_device = replace(
            updated_device,
            catalog_roots=(),
            audit_roots=(),
            neighborhoods=matching_neighborhoods,
        )
        started = (
            self._run_local(isolated_device, "up")
            if isolated_device.transport == "local"
            else self._run_remote(isolated_device, "up")
        )
        if not started.get("ok"):
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=registered,
                updated_device=updated_device,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "registered": registered,
                "started": started,
                "rollback": rollback,
            }
        members = []
        for neighborhood_result in started.get("neighborhoods", []):
            if not isinstance(neighborhood_result, dict):
                continue
            result = neighborhood_result.get("result")
            if not isinstance(result, dict):
                continue
            members.extend(
                member
                for member in result.get("members", [])
                if isinstance(member, dict)
                and member.get("rappid") == created["rappid"]
            )
        if len(members) != 1 or not isinstance(members[0].get("port"), int):
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=registered,
                updated_device=updated_device,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "registered": registered,
                "started": started,
                "error": "started buddy identity or port could not be proven",
                "rollback": rollback,
            }
        actual_port = int(members[0]["port"])
        try:
            handshake = runner(
                updated_device,
                "handshake",
                buddy_handshake_payload(
                    device.id,
                    name=created["name"],
                    rappid=created["rappid"],
                    port=actual_port,
                    identity_nonce=created["identity_nonce"],
                ),
            )
        except (OSError, RappHerdrError) as exc:
            handshake = {"ok": False, "error": str(exc)}
        if not handshake.get("ok") or not handshake.get("ready"):
            rollback = self._rollback_buddy(
                device,
                runner,
                created,
                registered=registered,
                updated_device=updated_device,
            )
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-create",
                "device": device.id,
                "created": created,
                "registered": registered,
                "started": started,
                "handshake": handshake,
                "actual_port": actual_port,
                "presence": "offline",
                "rollback": rollback,
            }
        return {
            "ok": bool(handshake.get("ok")),
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "action": "buddy-create",
            "device": device.id,
            "created": created,
            "registered": registered,
            "started": started,
            "handshake": handshake,
            "actual_port": actual_port,
            "presence": (
                "online"
                if handshake.get("ok") and handshake.get("ready")
                else "offline"
            ),
        }

    def _rollback_buddy(
        self,
        device: EstateDevice,
        runner,
        created: dict[str, Any],
        *,
        registered: dict[str, Any] | None,
        updated_device: EstateDevice | None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": True,
            "stopped": None,
            "manifest_restored": None,
            "deleted": None,
        }
        if updated_device is not None:
            matching = tuple(
                neighborhood
                for neighborhood in updated_device.neighborhoods
                if neighborhood.manifest == created["neighborhood"]["manifest"]
            )
            if len(matching) == 1:
                isolated = replace(
                    updated_device,
                    catalog_roots=(),
                    audit_roots=(),
                    neighborhoods=matching,
                )
                stopped = (
                    self._run_local(isolated, "down")
                    if isolated.transport == "local"
                    else self._run_remote(isolated, "down")
                )
                result["stopped"] = stopped
                if not stopped.get("ok"):
                    result["ok"] = False
                    result["error"] = (
                        "could not stop the created buddy; resources preserved"
                    )
                    return result

        if registered is not None:
            try:
                from .buddy import remove_buddy_neighborhood

                removed = remove_buddy_neighborhood(
                    self.estate.manifest_path,
                    device.id,
                    created["neighborhood"]["manifest"],
                    expected_hash=registered["manifest_hash_after"],
                )
                result["manifest_restored"] = bool(removed.get("ok"))
            except (OSError, UnicodeError, json.JSONDecodeError, RappHerdrError) as exc:
                result["ok"] = False
                result["manifest_restored"] = False
                result["error"] = f"cannot restore estate manifest: {exc}"
                return result
        try:
            deleted = runner(
                device,
                "delete",
                buddy_cleanup_payload(
                    device.id,
                    workspace=created["workspace"],
                    manifest=created["manifest"],
                    rappid=created["rappid"],
                    identity_nonce=created["identity_nonce"],
                ),
            )
            result["deleted"] = deleted
            result["ok"] = bool(deleted.get("ok"))
        except (OSError, RappHerdrError) as exc:
            result["ok"] = False
            result["error"] = f"cannot delete buddy resources: {exc}"
        return result

    def _buddy_records(self) -> list[dict[str, Any]]:
        status = self.run("status")
        devices = {
            device.id: device for device in self.estate.devices
        }
        candidates: list[dict[str, Any]] = []
        for device in self.estate.devices:
            if not device.enabled:
                continue
            for configured in device.neighborhoods:
                if (
                    configured.managed_by != BUDDY_SCHEMA
                    or configured.buddy_name is None
                ):
                    continue
                identity = str(
                    configured.buddy_rappid or configured.buddy_name
                )
                buddy_id = hashlib.sha256(
                    f"{device.id}\0{identity}".encode()
                ).hexdigest()[:20]
                candidates.append(
                    {
                        "id": buddy_id,
                        "name": configured.buddy_name,
                        "device": device.id,
                        "rappid": configured.buddy_rappid,
                        "presence": "offline",
                        "status": "offline",
                        "herdr_status": "down",
                        "transport": (
                            "local"
                            if device.transport == "local"
                            else "ssh-windows"
                            if device.os == "windows"
                            else "ssh-posix"
                        ),
                        "via_probe": False,
                        "ui": configured.buddy_ui,
                        "application_url": None,
                        "default_chat_url": None,
                        "_url": (
                            f"http://127.0.0.1:{configured.base_port}"
                        ),
                        "_device": device,
                        "_observed": False,
                    }
                )
        for observed in status.get("devices", []):
            if not isinstance(observed, dict):
                continue
            device_id = observed.get("device")
            device = devices.get(device_id)
            if device is None:
                continue
            for neighborhood in observed.get("neighborhoods", []):
                result = (
                    neighborhood.get("result")
                    if isinstance(neighborhood, dict)
                    else None
                )
                if not isinstance(result, dict):
                    continue
                configured = next(
                    (
                        item for item in device.neighborhoods
                        if _manifest_identity(item.manifest)
                        == _manifest_identity(neighborhood.get("manifest"))
                    ),
                    None,
                )
                for member in result.get("members", []):
                    if not isinstance(member, dict):
                        continue
                    url = member.get("url")
                    if not isinstance(url, str):
                        continue
                    is_probe = bool(
                        configured is not None
                        and configured.managed_by == PROBE_SCHEMA
                        and _manifest_identity(configured.manifest)
                        == _manifest_identity(PROBE_NEIGHBORHOOD_MANIFEST)
                        and member.get("rappid")
                        == probe_rappid(device.id)
                    )
                    target = device.probe_target if is_probe else None
                    runtime_probe_target = (
                        member.get("probe_relay_target")
                        if is_probe
                        else None
                    )
                    probe_target_matches = bool(
                        not is_probe
                        or (
                            target is not None
                            and runtime_probe_target == target.payload()
                        )
                    )
                    name = target.name if target else member.get("name")
                    rappid = target.rappid if target else member.get("rappid")
                    identity = str(rappid or name or member.get("pane_id"))
                    buddy_id = hashlib.sha256(
                        f"{device_id}\0{identity}".encode()
                    ).hexdigest()[:20]
                    healthy = bool(
                        member.get("healthy") and member.get("live")
                        and (
                            not is_probe
                            or (
                                member.get("probe_target_ready") is True
                                and probe_target_matches
                            )
                        )
                    )
                    candidates.append(
                        {
                            "id": buddy_id,
                            "name": str(name or "RAPP Neighbor"),
                            "device": device_id,
                            "rappid": rappid,
                            "presence": "online" if healthy else "offline",
                            "status": "ready" if healthy else "offline",
                            "herdr_status": member.get("agent_status"),
                            "transport": (
                                "local"
                                if device.transport == "local"
                                else "ssh-windows"
                                if device.os == "windows"
                                else "ssh-posix"
                            ),
                            "via_probe": is_probe,
                            "configuration_drift": bool(
                                is_probe and not probe_target_matches
                            ),
                            "ui": (
                                configured.buddy_ui
                                if configured is not None
                                else None
                            ),
                            "application_url": (
                                url
                                if configured is not None
                                and configured.buddy_ui == "rapplication"
                                and device.transport == "local"
                                else None
                            ),
                            "default_chat_url": (
                                f"{url}/?ui=chat"
                                if configured is not None
                                and configured.buddy_ui == "rapplication"
                                and device.transport == "local"
                                else None
                            ),
                            "_url": url,
                            "_device": device,
                            "_observed": True,
                        }
                    )
        selected: dict[str, dict[str, Any]] = {}
        for candidate in sorted(
            candidates,
            key=lambda item: (
                item["presence"] != "online",
                not bool(item["_observed"]),
                bool(item["via_probe"]),
            ),
        ):
            key = (
                f"{candidate['device']}\0"
                f"{candidate.get('rappid') or candidate['name']}"
            )
            selected.setdefault(key, candidate)
        return list(selected.values())

    @staticmethod
    def _public_buddy(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value for key, value in record.items()
            if not key.startswith("_")
        }

    def list_buddies(self) -> dict[str, Any]:
        buddies = [
            self._public_buddy(record)
            for record in self._buddy_records()
        ]
        buddies.sort(key=lambda item: (item["device"], item["name"]))
        return {
            "ok": True,
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "action": "buddy-list",
            "devices": sorted(
                device.id for device in self.estate.devices if device.enabled
            ),
            "buddies": buddies,
        }

    def chat_buddy(
        self,
        *,
        buddy_id: str,
        message: str,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        matches = [
            record for record in self._buddy_records()
            if record["id"] == buddy_id
        ]
        if len(matches) != 1:
            raise RappHerdrError("estate buddy is not uniquely available")
        buddy = matches[0]
        if buddy["presence"] != "online":
            raise RappHerdrError("estate buddy is offline")
        device = buddy["_device"]
        payload = buddy_chat_payload(
            device.id,
            url=buddy["_url"],
            message=message,
            session_id=session_id,
        )
        result = (
            self._run_local_buddy(device, "chat", payload)
            if device.transport == "local"
            else self._run_remote_buddy(device, "chat", payload)
        )
        if not result.get("ok"):
            return {
                "ok": False,
                "schema": ESTATE_SCHEMA,
                "estate": self.estate.name,
                "action": "buddy-chat",
                "buddy": self._public_buddy(buddy),
                "error": result.get("error") or "buddy did not answer",
            }
        return {
            "ok": True,
            "schema": ESTATE_SCHEMA,
            "estate": self.estate.name,
            "action": "buddy-chat",
            "buddy": {
                **self._public_buddy(buddy),
                "presence": "online",
                "status": "ready",
            },
            "response": result["response"],
            "session_id": result.get("session_id"),
            "responded_at": result.get("responded_at"),
        }
