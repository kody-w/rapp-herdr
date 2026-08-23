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
PROBE_NEIGHBORHOOD_NAME = "RAPP-Herdr Persistence Probe"
PROBE_NEIGHBORHOOD_RAPPID = (
    "rappid:@rapp/persistence-probe:"
    + hashlib.sha256(b"rapp-herdr-persistence-probe/1.0").hexdigest()
)
PROBE_NEIGHBORHOOD_MANIFEST = (
    "~/.rapp/neighborhoods/rapp-herdr-persistence-probe/neighborhood.json"
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_BRAINSTEM = r'''from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, value):
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        nonce = os.environ.get("RAPP_HERDR_LAUNCH_NONCE", "")
        if nonce:
            self.send_header("X-RAPP-Herdr-Launch", nonce)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.rstrip("/") != "/health":
            self.send_json(404, {"error": "not found"})
            return
        with state_lock:
            state = read_state()
        self.send_json(200, {
            "status": "ok",
            "service": "rapp-herdr-persistence-probe",
            "probe": state,
        })

    def do_POST(self):
        if self.path.rstrip("/") != "/chat":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 < length <= 100000:
            self.send_json(400, {"error": "invalid request body"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (UnicodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "invalid JSON"})
            return
        user_input = str(body.get("user_input") or "").strip()
        if not user_input:
            self.send_json(400, {"error": "user_input is required"})
            return
        with state_lock:
            state = read_state()
            messages = list(state.get("messages", []))
            messages.append({
                "content": user_input,
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            state["messages"] = messages[-100:]
            state["message_count"] = int(state.get("message_count", 0)) + 1
            write_state(state)
        self.send_json(200, {
            "response": "Persistence marker stored locally.",
            "session_id": "persistence-probe",
            "agent_logs": "persistence-probe",
            "probe": state,
        })

    def log_message(self, _format, *_args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        (
            os.environ.get("RAPP_HERDR_LISTEN_HOST", "127.0.0.1"),
            int(os.environ.get("PORT", "7199")),
        ),
        Handler,
    )
    server.serve_forever(poll_interval=0.25)
'''


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{field} must be a non-empty string")
    if "\0" in value or "\n" in value or "\r" in value:
        raise RappHerdrError(f"{field} contains an unsafe control character")
    return value.strip()


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RappHerdrError(f"{field} must be a non-negative integer")
    return value


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
    raw_workspace = inventory_root / f"rapp-herdr-persistence-probe-{device_id}"
    if raw_workspace.is_symlink():
        raise RappHerdrError(f"probe workspace cannot be a symlink: {raw_workspace}")
    workspace = raw_workspace.resolve()
    if workspace.parent != inventory_root:
        raise RappHerdrError("probe workspace escapes its inventory root")
    neighborhood_manifest = Path(
        _required_text(
            value.get("neighborhood_manifest"),
            "probe.neighborhood_manifest",
        )
    ).expanduser().absolute()
    return device_id, rappid, workspace, neighborhood_manifest, base_port


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"{label} must contain a JSON object: {path}")
    return value


def _claim_neighborhood(
    manifest: Path,
    *,
    marker: dict[str, Any],
    expected_manifest: dict[str, Any],
    expected_members: dict[str, Any],
) -> None:
    members = manifest.with_name("members.json")
    marker_path = manifest.with_name(".rapp-herdr-probe.json")
    for path in (manifest, members, marker_path):
        if path.is_symlink():
            raise RappHerdrError(f"probe neighborhood file cannot be a symlink: {path}")
    if marker_path.is_file():
        if _read_json(marker_path, "probe neighborhood marker") != marker:
            raise RappHerdrError(
                f"probe neighborhood ownership does not match: {manifest.parent}"
            )
    elif manifest.parent.exists():
        children = {child.name for child in manifest.parent.iterdir()}
        known = {"neighborhood.json", "members.json"}
        if children - known:
            raise RappHerdrError(
                f"refusing to replace unmanaged probe neighborhood: {manifest.parent}"
            )
        if manifest.is_file() and _read_json(
            manifest, "probe neighborhood manifest"
        ) != expected_manifest:
            raise RappHerdrError(
                f"refusing to replace unmanaged probe neighborhood: {manifest}"
            )
        if members.is_file() and _read_json(
            members, "probe neighborhood members"
        ) != expected_members:
            raise RappHerdrError(
                f"refusing to replace unmanaged probe neighborhood: {members}"
            )
    _write_json(marker_path, marker)
    _write_json(manifest, expected_manifest)
    _write_json(members, expected_members)


def _seed(value: dict[str, Any]) -> dict[str, Any]:
    device_id, rappid, workspace, manifest, base_port = _paths(value)
    marker_path = workspace / ".rapp-herdr-probe.json"
    if marker_path.is_symlink():
        raise RappHerdrError(f"probe marker cannot be a symlink: {marker_path}")
    if workspace.exists() and not marker_path.is_file():
        raise RappHerdrError(
            f"refusing to replace unmanaged probe workspace: {workspace}"
        )
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = {
        "schema": PROBE_SCHEMA,
        "device_id": device_id,
        "rappid": rappid,
    }
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
            "A bounded local Twin used only to prove that identity and memory "
            "survive runtime restarts.\n"
        ).encode(),
    )
    _atomic_write(workspace / "brainstem.py", _BRAINSTEM.encode())
    # Probes reuse the already-proven Brainstem interpreter selected in the
    # estate manifest. Omitting requirements makes bootstrap=False verify its
    # imports without asking pip to mutate an externally managed environment.
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
                "seeded_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(),
                ),
                "boot_count": 0,
                "message_count": 0,
                "messages": [],
            },
        )

    expected_manifest = {
        "schema": "rapp-neighborhood/1.0",
        "name": "rapp-herdr-persistence-probe",
        "display_name": PROBE_NEIGHBORHOOD_NAME,
        "neighborhood_rappid": PROBE_NEIGHBORHOOD_RAPPID,
        "members_path": "members.json",
    }
    expected_members = {
        "schema": "rapp-neighborhood-members/1.0",
        "neighborhood_rappid": PROBE_NEIGHBORHOOD_RAPPID,
        "members": [{"rappid": rappid, "role": "persistence-probe"}],
    }
    _claim_neighborhood(
        manifest,
        marker=marker,
        expected_manifest=expected_manifest,
        expected_members=expected_members,
    )
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
        raise RappHerdrError(f"persistence probe is not reachable at {url}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError("persistence probe returned an invalid response")
    return value


def _observe(value: dict[str, Any], *, mark: bool) -> dict[str, Any]:
    device_id, rappid, workspace, _manifest, base_port = _paths(value)
    if mark:
        text = _required_text(value.get("message"), "probe.message")
        response = _request_json(
            f"http://127.0.0.1:{base_port}/chat",
            method="POST",
            body={"user_input": text},
        )
    else:
        response = _request_json(f"http://127.0.0.1:{base_port}/health")
    state_path = workspace / ".brainstem_data" / "persistence_probe.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot read probe state {state_path}: {exc}") from exc
    if state.get("rappid") != rappid or state.get("device_id") != device_id:
        raise RappHerdrError("persistence probe state identity diverged")
    remote_state = response.get("probe")
    if not isinstance(remote_state, dict):
        raise RappHerdrError("persistence probe response omitted its state")
    if remote_state.get("survival_marker") != state.get("survival_marker"):
        raise RappHerdrError("persistence probe survival marker diverged")
    mark_path = workspace / ".rapp-herdr-probe-mark.json"
    if mark_path.is_symlink():
        raise RappHerdrError(f"probe mark cannot be a symlink: {mark_path}")
    if mark:
        _write_json(
            mark_path,
            {
                "schema": PROBE_SCHEMA,
                "device_id": device_id,
                "rappid": rappid,
                "message": text,
                "marked_boot_count": _nonnegative_int(
                    state.get("boot_count"),
                    "probe boot_count",
                ),
                "marked_message_count": _nonnegative_int(
                    state.get("message_count"),
                    "probe message_count",
                ),
                "survival_marker": state.get("survival_marker"),
            },
        )
    else:
        if not mark_path.is_file():
            raise RappHerdrError("persistence probe has not been marked yet")
        mark_record = _read_json(mark_path, "persistence probe mark")
        if (
            mark_record.get("schema") != PROBE_SCHEMA
            or mark_record.get("device_id") != device_id
            or mark_record.get("rappid") != rappid
            or mark_record.get("survival_marker") != state.get("survival_marker")
        ):
            raise RappHerdrError("persistence probe mark identity diverged")
        marked_message = mark_record.get("message")
        messages = state.get("messages")
        if (
            not isinstance(marked_message, str)
            or not isinstance(messages, list)
            or not any(
                isinstance(item, dict)
                and item.get("content") == marked_message
                for item in messages
            )
        ):
            raise RappHerdrError("persistence probe mark did not survive")
        message_count = _nonnegative_int(
            state.get("message_count"),
            "probe message_count",
        )
        marked_message_count = _nonnegative_int(
            mark_record.get("marked_message_count"),
            "marked probe message_count",
        )
        if message_count < marked_message_count:
            raise RappHerdrError("persistence probe message count rolled back")
        boot_count = _nonnegative_int(
            state.get("boot_count"),
            "probe boot_count",
        )
        marked_boot_count = _nonnegative_int(
            mark_record.get("marked_boot_count"),
            "marked probe boot_count",
        )
        if boot_count <= marked_boot_count:
            raise RappHerdrError(
                "persistence probe has not restarted since it was marked"
            )
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
    if not isinstance(value, dict) or not isinstance(value.get("devices"), list):
        raise RappHerdrError("estate manifest has no device array")
    changed = False
    configured: list[str] = []
    for device in value["devices"]:
        if not isinstance(device, dict) or device.get("id") not in device_ids:
            continue
        roots = device.get("inventory_roots", ["~/.rapp/twins"])
        if not isinstance(roots, list) or not roots:
            raise RappHerdrError(
                f"device {device.get('id')} has no inventory root for its probe"
            )
        neighborhoods = device.setdefault("neighborhoods", [])
        if not isinstance(neighborhoods, list):
            raise RappHerdrError(
                f"device {device.get('id')} neighborhoods must be an array"
            )
        existing = [
            item
            for item in neighborhoods
            if isinstance(item, dict)
            and item.get("manifest") == PROBE_NEIGHBORHOOD_MANIFEST
        ]
        desired = {
            "manifest": PROBE_NEIGHBORHOOD_MANIFEST,
            "estate_roots": [roots[0]],
            "base_port": base_port,
            "brainstem_python": probe_brainstem_python(
                str(device.get("os") or "posix")
            ),
            "bootstrap": False,
            "listen_host": "127.0.0.1",
            "entrypoint": "brainstem.py",
            "managed_by": PROBE_SCHEMA,
        }
        if existing:
            if (
                len(existing) != 1
                or existing[0].get("managed_by") != PROBE_SCHEMA
            ):
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
    from .backup import import_estate_backup

    result = import_estate_backup(manifest_path, value)
    return {
        "ok": True,
        "changed": True,
        "devices": configured,
        "previous_manifest": result["previous_manifest"],
    }
