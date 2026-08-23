from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .model import RappHerdrError

PROBE_SCHEMA = "rapp-herdr-persistence-probe/1.0"
PROBE_NEIGHBORHOOD_RAPPID = (
    "rappid:@rapp/persistence-probe:"
    + hashlib.sha256(PROBE_SCHEMA.encode()).hexdigest()
)
PROBE_NEIGHBORHOOD_MANIFEST = (
    "~/.rapp/neighborhoods/rapp-herdr-persistence-probe/neighborhood.json"
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_BRAINSTEM = r'''from __future__ import annotations
import json, os, threading, time
from pathlib import Path
from flask import Flask, jsonify, request

app = Flask(__name__)
state_path = Path(".brainstem_data") / "persistence_probe.json"
state_path.parent.mkdir(parents=True, exist_ok=True)
state_lock = threading.Lock()

def read_state():
    return json.loads(state_path.read_text(encoding="utf-8"))

def write_state(value):
    temporary = state_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, state_path)

with state_lock:
    startup = read_state()
    startup["boot_count"] = int(startup.get("boot_count", 0)) + 1
    startup["last_started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_state(startup)

@app.get("/health")
def health():
    with state_lock:
        state = read_state()
    return jsonify({"status": "ok", "service": "rapp-herdr-persistence-probe", "probe": state})

@app.post("/chat")
def chat():
    body = request.get_json(silent=True) or {}
    user_input = str(body.get("user_input") or "").strip()
    if not user_input:
        return jsonify({"error": "user_input is required"}), 400
    with state_lock:
        state = read_state()
        messages = list(state.get("messages", []))
        messages.append({"content": user_input, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        state["messages"] = messages[-100:]
        state["message_count"] = int(state.get("message_count", 0)) + 1
        write_state(state)
    return jsonify({"response": "Persistence marker stored locally.", "session_id": "persistence-probe", "agent_logs": "persistence-probe", "probe": state})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "7199")), use_reloader=False)
'''


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{field} must be a non-empty string")
    if any(character in value for character in ("\0", "\n", "\r")):
        raise RappHerdrError(f"{field} contains an unsafe control character")
    return value.strip()


def probe_rappid(device_id: str) -> str:
    digest = hashlib.sha256(
        f"rapp-herdr-persistence-probe\0{device_id}".encode()
    ).hexdigest()
    return f"rappid:@rapp/persistence-probe-{device_id}:{digest}"


def probe_brainstem_python(device_os: str) -> str:
    return (
        "~/.brainstem/venv/Scripts/python.exe"
        if device_os == "windows"
        else "~/.brainstem/venv/bin/python"
    )


def probe_payload(
    device_id: str,
    inventory_root: str,
    *,
    base_port: int,
    message: str | None = None,
    neighborhood_manifest: str = PROBE_NEIGHBORHOOD_MANIFEST,
) -> dict[str, Any]:
    return {
        "schema": PROBE_SCHEMA,
        "device_id": device_id,
        "inventory_root": inventory_root,
        "neighborhood_manifest": neighborhood_manifest,
        "rappid": probe_rappid(device_id),
        "base_port": base_port,
        "message": message,
    }


def encode_probe_payload(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).decode()


def decode_probe_payload(encoded: str) -> dict[str, Any]:
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded).decode())
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid encoded probe payload: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError("probe payload must contain an object")
    return value


def _atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        path.chmod(mode)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode(),
    )


def _paths(value: dict[str, Any]) -> tuple[str, str, Path, Path, int]:
    if value.get("schema") != PROBE_SCHEMA:
        raise RappHerdrError(f"probe payload must use schema {PROBE_SCHEMA!r}")
    device_id = _required_text(value.get("device_id"), "probe.device_id")
    if not _SAFE_ID.fullmatch(device_id):
        raise RappHerdrError(f"unsafe probe device id: {device_id!r}")
    rappid = _required_text(value.get("rappid"), "probe.rappid")
    if rappid != probe_rappid(device_id):
        raise RappHerdrError("probe RAPPID does not match its device")
    base_port = value.get("base_port")
    if not isinstance(base_port, int) or not 1 <= base_port <= 65535:
        raise RappHerdrError("probe.base_port must be an integer from 1 to 65535")
    inventory_root = Path(
        _required_text(value.get("inventory_root"), "probe.inventory_root")
    ).expanduser().resolve()
    workspace = (
        inventory_root / f"rapp-herdr-persistence-probe-{device_id}"
    ).resolve()
    if workspace.parent != inventory_root:
        raise RappHerdrError("probe workspace escapes its inventory root")
    manifest = Path(
        _required_text(
            value.get("neighborhood_manifest"),
            "probe.neighborhood_manifest",
        )
    ).expanduser().resolve()
    return device_id, rappid, workspace, manifest, base_port


def _seed(value: dict[str, Any]) -> dict[str, Any]:
    device_id, rappid, workspace, manifest, base_port = _paths(value)
    marker_path = workspace / ".rapp-herdr-probe.json"
    marker = {"schema": PROBE_SCHEMA, "device_id": device_id, "rappid": rappid}
    if workspace.exists() and not marker_path.is_file():
        raise RappHerdrError(
            f"refusing to replace unmanaged probe workspace: {workspace}"
        )
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    if marker_path.is_file():
        try:
            existing = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RappHerdrError(f"invalid probe marker {marker_path}: {exc}") from exc
        if existing != marker:
            raise RappHerdrError(
                f"probe workspace ownership does not match: {workspace}"
            )
    _write_json(marker_path, marker)
    _write_json(
        workspace / "rappid.json",
        {
            "schema": "rapp/1",
            "rappid": rappid,
            "kind": "twin",
            "name": f"persistence-probe-{device_id}",
            "display_name": f"Persistence Probe - {device_id}",
        },
    )
    _atomic_write(
        workspace / "soul.md",
        (
            f"# Persistence Probe - {device_id}\n\n"
            "A bounded local Twin used only to prove identity and memory "
            "survive runtime restarts.\n"
        ).encode(),
    )
    _atomic_write(workspace / "brainstem.py", _BRAINSTEM.encode())
    (workspace / "requirements.txt").unlink(missing_ok=True)
    (workspace / "agents").mkdir(exist_ok=True, mode=0o700)
    state_path = workspace / ".brainstem_data" / "persistence_probe.json"
    if not state_path.is_file():
        _write_json(
            state_path,
            {
                "schema": PROBE_SCHEMA,
                "device_id": device_id,
                "rappid": rappid,
                "survival_marker": hashlib.sha256(
                    f"{rappid}\0survival".encode()
                ).hexdigest(),
                "seeded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "boot_count": 0,
                "message_count": 0,
                "messages": [],
            },
        )
    neighborhood_value = {
        "schema": "rapp-neighborhood/1.0",
        "name": "rapp-herdr-persistence-probe",
        "display_name": "RAPP-Herdr Persistence Probe",
        "neighborhood_rappid": PROBE_NEIGHBORHOOD_RAPPID,
        "members_path": "members.json",
    }
    members_value = {
        "schema": "rapp-neighborhood-members/1.0",
        "neighborhood_rappid": PROBE_NEIGHBORHOOD_RAPPID,
        "members": [{"rappid": rappid, "role": "persistence-probe"}],
    }
    neighborhood_marker = manifest.parent / ".rapp-herdr-probe-neighborhood.json"
    marker_value = {
        "schema": PROBE_SCHEMA,
        "neighborhood_rappid": PROBE_NEIGHBORHOOD_RAPPID,
    }
    existing_files = {
        manifest: neighborhood_value,
        manifest.with_name("members.json"): members_value,
    }
    if neighborhood_marker.is_file():
        try:
            existing_marker = json.loads(
                neighborhood_marker.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RappHerdrError(
                f"invalid probe neighborhood marker {neighborhood_marker}: {exc}"
            ) from exc
        if existing_marker != marker_value:
            raise RappHerdrError("probe neighborhood ownership marker diverged")
    elif any(path.exists() for path in existing_files):
        for path, expected in existing_files.items():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise RappHerdrError(
                    f"refusing to replace unmanaged probe neighborhood: {path}"
                ) from exc
            if existing != expected:
                raise RappHerdrError(
                    f"refusing to replace unmanaged probe neighborhood: {path}"
                )
    _write_json(neighborhood_marker, marker_value)
    _write_json(manifest, neighborhood_value)
    _write_json(manifest.with_name("members.json"), members_value)
    return {
        "ok": True,
        "device": device_id,
        "workspace": str(workspace),
        "manifest": str(manifest),
        "rappid": rappid,
        "port": base_port,
        "state": json.loads(state_path.read_text(encoding="utf-8")),
    }


def _request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            value = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RappHerdrError(
            f"persistence probe is not reachable at {url}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise RappHerdrError("persistence probe returned an invalid response")
    return value


def _observe(value: dict[str, Any], *, mark: bool) -> dict[str, Any]:
    device_id, rappid, workspace, _manifest, base_port = _paths(value)
    response = (
        _request_json(
            f"http://127.0.0.1:{base_port}/chat",
            method="POST",
            body={
                "user_input": _required_text(value.get("message"), "probe.message")
            },
        )
        if mark
        else _request_json(f"http://127.0.0.1:{base_port}/health")
    )
    state_path = workspace / ".brainstem_data" / "persistence_probe.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot read probe state {state_path}: {exc}") from exc
    remote_state = response.get("probe")
    if (
        state.get("rappid") != rappid
        or state.get("device_id") != device_id
        or not isinstance(remote_state, dict)
        or remote_state.get("survival_marker") != state.get("survival_marker")
    ):
        raise RappHerdrError("persistence probe state identity diverged")
    return {
        "ok": True,
        "device": device_id,
        "rappid": rappid,
        "port": base_port,
        "state": state,
    }


def run_probe_device(action: str, value: dict[str, Any]) -> dict[str, Any]:
    if action == "seed":
        return _seed(value)
    if action == "mark":
        return _observe(value, mark=True)
    if action == "verify":
        return _observe(value, mark=False)
    raise RappHerdrError(f"unsupported persistence probe action: {action}")


def add_probe_neighborhoods(
    manifest: str | Path,
    device_ids: set[str],
    *,
    base_port: int,
) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot update estate manifest {manifest_path}: {exc}") from exc
    devices = value.get("devices") if isinstance(value, dict) else None
    if not isinstance(devices, list):
        raise RappHerdrError("estate manifest has no device array")
    changed = False
    configured = []
    for device in devices:
        if not isinstance(device, dict) or device.get("id") not in device_ids:
            continue
        roots = device.get("inventory_roots", ["~/.rapp/twins"])
        neighborhoods = device.setdefault("neighborhoods", [])
        if not isinstance(roots, list) or not roots or not isinstance(neighborhoods, list):
            raise RappHerdrError(f"device {device.get('id')} has invalid probe roots")
        desired = {
            "manifest": PROBE_NEIGHBORHOOD_MANIFEST,
            "estate_roots": [roots[0]],
            "base_port": base_port,
            "brainstem_python": probe_brainstem_python(str(device.get("os") or "posix")),
            "bootstrap": False,
            "listen_host": "127.0.0.1",
            "entrypoint": "brainstem.py",
            "managed_by": PROBE_SCHEMA,
        }
        existing = [
            item
            for item in neighborhoods
            if isinstance(item, dict)
            and item.get("manifest") == PROBE_NEIGHBORHOOD_MANIFEST
        ]
        if existing:
            if len(existing) != 1 or existing[0].get("managed_by") != PROBE_SCHEMA:
                raise RappHerdrError(
                    f"device {device.get('id')} has a conflicting probe neighborhood"
                )
            if existing[0] != desired:
                existing[0].clear()
                existing[0].update(desired)
                changed = True
        else:
            neighborhoods.append(desired)
            changed = True
        configured.append(str(device["id"]))
    if set(configured) != device_ids:
        raise RappHerdrError("not every seeded device exists in the estate manifest")
    if not changed:
        return {"ok": True, "changed": False, "devices": configured}
    from .backup import replace_estate_manifest

    result = replace_estate_manifest(manifest_path, value)
    return {
        "ok": True,
        "changed": True,
        "devices": configured,
        "previous_manifest": result["previous_manifest"],
    }
