from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
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
import contextlib, hashlib, json, os, threading, time, urllib.error, urllib.request
from pathlib import Path
from flask import Flask, jsonify, request

app = Flask(__name__)
state_path = Path(".brainstem_data") / "persistence_probe.json"
file_lock_path = state_path.with_suffix(".lock")
state_path.parent.mkdir(parents=True, exist_ok=True)
state_lock = threading.Lock()
relay_lock = threading.Lock()

def read_state():
    return json.loads(state_path.read_text(encoding="utf-8"))

def write_state(value):
    temporary = state_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, state_path)

@contextlib.contextmanager
def state_file_lock(timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        try:
            file_lock_path.mkdir()
            break
        except FileExistsError:
            try:
                if time.time() - file_lock_path.stat().st_mtime > 300:
                    file_lock_path.rmdir()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("probe state lock timed out")
            time.sleep(0.05)
    try:
        yield
    finally:
        file_lock_path.rmdir()

with relay_lock, state_file_lock(), state_lock:
    startup = read_state()
    startup["boot_count"] = int(startup.get("boot_count", 0)) + 1
    startup["last_started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_state(startup)

@app.get("/health")
def health():
    with state_file_lock(), state_lock:
        state = read_state()
    target = state.get("relay_target")
    target_healthy = False
    if isinstance(target, dict):
        try:
            with urllib.request.urlopen(target["url"] + "/health", timeout=1) as response:
                payload = response.read(64 * 1024 + 1)
                value = json.loads(payload) if len(payload) <= 64 * 1024 else None
                target_healthy = (
                    200 <= int(response.status) < 300
                    and isinstance(value, dict)
                    and value.get("status") in {"ok", "ready"}
                )
        except (
            OSError,
            ValueError,
            urllib.error.URLError,
            json.JSONDecodeError,
        ):
            target_healthy = False
    last_relay = state.get("last_relay")
    target_revision = int(state.get("target_revision", 0))
    target_ready = bool(
        target_healthy
        and isinstance(last_relay, dict)
        and last_relay.get("responded") is True
        and last_relay.get("target_revision") == target_revision
    )
    probe = {
        "schema": state.get("schema"),
        "device_id": state.get("device_id"),
        "rappid": state.get("rappid"),
        "survival_marker": state.get("survival_marker"),
        "relay_target": target,
        "target_revision": target_revision,
        "relay_count": int(state.get("relay_count", 0)),
        "last_relay": last_relay,
    }
    return jsonify({
        "status": "ok",
        "service": "rapp-herdr-persistence-probe",
        "target_healthy": target_healthy,
        "target_ready": target_ready,
        "probe": probe,
    })

def relay_turn(target, user_input, session_id):
    body = {
        "schema": "rapp-chat/1.0",
        "message": user_input,
        "user_input": user_input,
    }
    if session_id:
        body["session_id"] = session_id
    relay_request = urllib.request.Request(
        target["url"] + "/chat",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(relay_request, timeout=180) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise ValueError("target returned a non-object response")
    text = value.get("response") or value.get("content") or value.get("assistant_response")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("target returned no response text")
    return text.strip(), value.get("session_id")

@app.post("/chat")
def chat():
    body = request.get_json(silent=True) or {}
    user_input = str(body.get("user_input") or "").strip()
    if not user_input:
        return jsonify({"error": "user_input is required"}), 400
    recorded_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with state_file_lock(), state_lock:
        state = read_state()
        target = state.get("relay_target")
        if not isinstance(target, dict):
            return jsonify({"error": "probe relay target is not configured", "probe": state}), 503
        messages = list(state.get("messages", []))
        message_count = int(state.get("message_count", 0)) + 1
        relay_id = "%s-%s-%s" % (state.get("device_id"), message_count, time.time_ns())
        messages.append({"content": user_input, "recorded_at": recorded_at, "relay_id": relay_id})
        state["messages"] = messages[-100:]
        state["message_count"] = message_count
        write_state(state)
    sent_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with relay_lock:
        with state_file_lock(), state_lock:
            state = read_state()
            target = state["relay_target"]
            target_revision = int(state.get("target_revision", 0))
            target_session_id = state.get("target_session_id")
        try:
            response_text, target_session_id = relay_turn(
                target,
                user_input,
                target_session_id,
            )
            receipt = {
                "relay_id": relay_id,
                "target_name": target["name"],
                "configured_target_rappid": target.get("rappid"),
                "sent_at": sent_at,
                "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target_revision": target_revision,
                "responded": True,
                "response_sha256": hashlib.sha256(response_text.encode()).hexdigest(),
            }
            with state_file_lock(), state_lock:
                state = read_state()
                if (
                    int(state.get("target_revision", 0)) != target_revision
                    or state.get("relay_target") != target
                ):
                    return jsonify({
                        "error": "probe relay target changed during chat",
                        "relay": dict(receipt, responded=False, stale_target=True),
                        "probe": state,
                    }), 409
                state["target_session_id"] = target_session_id
                state["relay_count"] = int(state.get("relay_count", 0)) + 1
                state["last_relay"] = receipt
                relays = list(state.get("relays", []))
                relays.append(receipt)
                state["relays"] = relays[-50:]
                write_state(state)
            return jsonify({
                "response": response_text,
                "session_id": target_session_id or "persistence-probe-relay",
                "agent_logs": "persistence-probe->%s" % target["name"],
                "probe": state,
                "relay": receipt,
            })
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            receipt = {
                "relay_id": relay_id,
                "target_name": target["name"],
                "configured_target_rappid": target.get("rappid"),
                "sent_at": sent_at,
                "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target_revision": target_revision,
                "responded": False,
                "error": type(exc).__name__,
            }
            with state_file_lock(), state_lock:
                state = read_state()
                if (
                    int(state.get("target_revision", 0)) != target_revision
                    or state.get("relay_target") != target
                ):
                    return jsonify({
                        "error": "probe relay target changed during chat",
                        "relay": dict(receipt, stale_target=True),
                        "probe": state,
                    }), 409
                state["last_relay"] = receipt
                relays = list(state.get("relays", []))
                relays.append(receipt)
                state["relays"] = relays[-50:]
                write_state(state)
            return jsonify({"error": "local Twin relay failed", "relay": receipt, "probe": state}), 502

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "7199")), use_reloader=False)
'''


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{field} must be a non-empty string")
    if any(character in value for character in ("\0", "\n", "\r")):
        raise RappHerdrError(f"{field} contains an unsafe control character")
    return value.strip()


def _relay_target(value: dict[str, Any], base_port: int) -> dict[str, Any]:
    raw = value.get("relay_target")
    if not isinstance(raw, dict):
        raise RappHerdrError(
            "probe.relay_target must identify a real local Twin"
        )
    name = _required_text(raw.get("name"), "probe.relay_target.name")
    url = _required_text(raw.get("url"), "probe.relay_target.url").rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.port is None
        or not 1 <= parsed.port <= 65535
        or parsed.port == base_port
    ):
        raise RappHerdrError(
            "probe.relay_target.url must be a different loopback HTTP port"
        )
    return {
        "name": name,
        "url": url,
        "rappid": (
            _required_text(raw.get("rappid"), "probe.relay_target.rappid")
            if raw.get("rappid") is not None
            else None
        ),
    }


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
    relay_target: dict[str, Any] | None = None,
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
        "relay_target": relay_target,
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


@contextmanager
def _probe_state_lock(state_path: Path, timeout: float = 10) -> Any:
    lock_path = state_path.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    deadline = time.monotonic() + timeout
    while True:
        try:
            lock_path.mkdir()
            break
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > 300:
                    lock_path.rmdir()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RappHerdrError(
                    f"persistence probe state lock timed out: {lock_path}"
                )
            time.sleep(0.05)
    try:
        yield
    finally:
        try:
            lock_path.rmdir()
        except OSError as exc:
            raise RappHerdrError(
                f"cannot release persistence probe state lock: {lock_path}"
            ) from exc


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
    relay_target = _relay_target(value, base_port)
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
            "survive runtime restarts by relaying every chat turn to a "
            "designated real local Twin on this device.\n"
        ).encode(),
    )
    _atomic_write(workspace / "brainstem.py", _BRAINSTEM.encode())
    _atomic_write(
        workspace / "requirements.txt",
        b"flask\nrequests\npython-dotenv\n",
        0o644,
    )
    (workspace / "agents").mkdir(exist_ok=True, mode=0o700)
    state_path = workspace / ".brainstem_data" / "persistence_probe.json"
    with _probe_state_lock(state_path):
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise RappHerdrError(f"invalid probe state {state_path}: {exc}") from exc
            if state.get("device_id") != device_id or state.get("rappid") != rappid:
                raise RappHerdrError("existing probe state identity diverged")
        else:
            state = {
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
                "relay_count": 0,
                "relays": [],
                "target_revision": 0,
            }
        if state.get("relay_target") != relay_target:
            state.pop("target_session_id", None)
            state.pop("last_relay", None)
            state["target_revision"] = int(state.get("target_revision", 0)) + 1
        state["relay_target"] = relay_target
        _write_json(state_path, state)
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
        "relay_target": relay_target,
        "state": json.loads(state_path.read_text(encoding="utf-8")),
    }


def _request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 5,
) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read()
        finally:
            exc.close()
        try:
            value = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as decode_exc:
            raise RappHerdrError(
                f"persistence probe returned HTTP {exc.code} with invalid JSON"
            ) from decode_exc
        if not isinstance(value, dict):
            raise RappHerdrError(
                f"persistence probe returned HTTP {exc.code} with an invalid response"
            )
        value["_http_status"] = int(exc.code)
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
            timeout=190,
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
    relay_target = _relay_target(value, base_port)
    relay = (
        response.get("relay")
        if mark
        else (
            remote_state.get("last_relay")
            if isinstance(remote_state, dict)
            else None
        )
    )
    if (
        state.get("rappid") != rappid
        or state.get("device_id") != device_id
        or not isinstance(remote_state, dict)
        or remote_state.get("survival_marker") != state.get("survival_marker")
        or remote_state.get("relay_target") != relay_target
    ):
        raise RappHerdrError("persistence probe state identity diverged")
    if (
        not isinstance(relay, dict)
        or relay.get("responded") is not True
        or relay.get("target_name") != relay_target["name"]
        or relay.get("configured_target_rappid") != relay_target["rappid"]
    ):
        return {
            "ok": False,
            "device": device_id,
            "rappid": rappid,
            "port": base_port,
            "state": state,
            "relay": relay,
            "error": "persistence probe did not receive a local Twin reply",
            "reachable": True,
        }
    return {
        "ok": True,
        "device": device_id,
        "rappid": rappid,
        "port": base_port,
        "state": state,
        "relay": relay,
    }


def run_probe_device(action: str, value: dict[str, Any]) -> dict[str, Any]:
    if action == "seed":
        return _seed(value)
    if action == "mark":
        return _observe(value, mark=True)
    if action == "verify":
        return _observe(value, mark=True)
    raise RappHerdrError(f"unsupported persistence probe action: {action}")


def add_probe_neighborhoods(
    manifest: str | Path,
    device_ids: set[str],
    *,
    base_port: int,
) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    try:
        manifest_bytes = manifest_path.read_bytes()
        value = json.loads(manifest_bytes)
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

    result = replace_estate_manifest(
        manifest_path,
        value,
        expected_hash=hashlib.sha256(manifest_bytes).hexdigest(),
    )
    return {
        "ok": True,
        "changed": True,
        "devices": configured,
        "previous_manifest": result["previous_manifest"],
    }
