from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .model import RappHerdrError

BUDDY_SCHEMA = "rapp-herdr-buddy/1.0"
_SAFE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_OWNER = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_CUSTOM_UI_WORDS = {
    "builder",
    "dashboard",
    "monitor",
    "portal",
    "report",
    "studio",
    "tracker",
    "visual",
    "workflow",
}


def _required_text(value: Any, field: str, limit: int = 4_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{field} must be a non-empty string")
    text = value.strip()
    if len(text) > limit or any(character in text for character in ("\0", "\r")):
        raise RappHerdrError(f"{field} is invalid")
    return text


def _manifest_text(value: Any, field: str, limit: int) -> str:
    text = _required_text(value, field, limit)
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise RappHerdrError(f"{field} contains an unsafe control character")
    return text


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug or not _SAFE_ID.fullmatch(slug):
        raise RappHerdrError("buddy name must contain letters or numbers")
    return slug[:48].rstrip("-")


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


def _write_text(path: Path, value: str, mode: int = 0o600) -> None:
    _atomic_write(path, value.encode(), mode)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode(),
    )


def _mint_rappid(owner: str, slug: str) -> str:
    if not _OWNER.fullmatch(owner) or len(owner) > 39:
        raise RappHerdrError("buddy owner is not a canonical RAPP/1 owner")
    identifier = uuid.uuid4()
    tail = hashlib.sha256(b"rapp/1:rappid\n" + identifier.bytes).hexdigest()
    return f"rappid:@{owner}/{slug}:{tail}"


def _select_port(start: int, end: int = 7299) -> int:
    if not 7200 <= start <= end <= 7299:
        raise RappHerdrError("buddy port range must stay within 7200-7299")
    for port in range(start, end + 1):
        with socket.socket() as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                candidate.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RappHerdrError("no free RAPP buddy port is available")


def _ui_mode(requested: str, role: str) -> str:
    if requested not in {"auto", "chat", "rapplication"}:
        raise RappHerdrError("buddy ui must be auto, chat, or rapplication")
    if requested != "auto":
        return requested
    words = set(re.findall(r"[a-z0-9]+", role.lower()))
    return "rapplication" if words.intersection(_CUSTOM_UI_WORDS) else "chat"


def _ready_response(value: Any) -> bool:
    return isinstance(value, str) and re.search(r"\bREADY\s*$", value) is not None


def buddy_payload(
    device_id: str,
    inventory_root: str,
    *,
    owner: str,
    name: str,
    role: str,
    ui: str = "auto",
    port_start: int = 7200,
    neighborhood_root: str = "~/.rapp/neighborhoods/rapp-herdr-buddies",
    brainstem_root: str = "~/.brainstem/src/rapp_brainstem",
) -> dict[str, Any]:
    return {
        "schema": BUDDY_SCHEMA,
        "device_id": device_id,
        "owner": owner,
        "inventory_root": inventory_root,
        "name": name,
        "role": role,
        "ui": ui,
        "port_start": port_start,
        "neighborhood_root": neighborhood_root,
        "brainstem_root": brainstem_root,
    }


def buddy_handshake_payload(
    device_id: str,
    *,
    name: str,
    rappid: str,
    port: int,
    identity_nonce: str,
) -> dict[str, Any]:
    return {
        "schema": BUDDY_SCHEMA,
        "device_id": device_id,
        "name": name,
        "rappid": rappid,
        "port": port,
        "identity_nonce": identity_nonce,
    }


def buddy_cleanup_payload(
    device_id: str,
    *,
    workspace: str,
    manifest: str,
    rappid: str,
    identity_nonce: str,
) -> dict[str, Any]:
    return {
        "schema": BUDDY_SCHEMA,
        "device_id": device_id,
        "workspace": workspace,
        "manifest": manifest,
        "rappid": rappid,
        "identity_nonce": identity_nonce,
    }


def buddy_chat_payload(
    device_id: str,
    *,
    url: str,
    message: str,
    session_id: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": BUDDY_SCHEMA,
        "device_id": device_id,
        "url": url,
        "message": message,
        "session_id": session_id,
    }


def encode_buddy_payload(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).decode()


def decode_buddy_payload(encoded: str) -> dict[str, Any]:
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded).decode())
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid encoded buddy payload: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError("buddy payload must contain an object")
    return value


def _role_agent(name: str, role: str) -> str:
    return f'''"""Device-local generated buddy role contract."""
import json

try:
    from agents.basic_agent import BasicAgent
except Exception:
    class BasicAgent:
        def __init__(self, name=None, metadata=None):
            self.name = name
            self.metadata = metadata or {{}}


class BuddyRoleAgent(BasicAgent):
    def __init__(self):
        self.name = "BuddyRole"
        self.metadata = {{
            "name": self.name,
            "description": {json.dumps(role)},
            "parameters": {{
                "type": "object",
                "properties": {{
                    "request": {{"type": "string", "description": "Role-specific request."}}
                }},
                "required": []
            }}
        }}
        super().__init__(self.name, self.metadata)

    def perform(self, **kwargs):
        return json.dumps({{
            "status": "ready",
            "buddy": {json.dumps(name)},
            "role": {json.dumps(role)},
            "request": str(kwargs.get("request") or "")
        }})
'''


def _wrapper(
    workspace: Path,
    brainstem_root: Path,
    custom_ui: bool,
    rappid: str,
    identity_nonce: str,
) -> str:
    index_override = ""
    if custom_ui:
        index_override = f'''
    def buddy_index():
        if flask.request.args.get("ui") == "chat":
            return flask.send_from_directory({str(brainstem_root)!r}, "index.html")
        return flask.send_from_directory({str(workspace / "ui")!r}, "index.html")
    app.view_functions["index"] = buddy_index
    app.add_url_rule(
        "/buddy.css",
        "buddy_css",
        lambda: flask.send_from_directory({str(workspace / "ui")!r}, "styles.css"),
    )
    app.add_url_rule(
        "/buddy.js",
        "buddy_js",
        lambda: flask.send_from_directory({str(workspace / "ui")!r}, "ui.js"),
    )
'''
    return f'''from __future__ import annotations
import os, runpy
from pathlib import Path
import flask

workspace = Path({str(workspace)!r})
os.environ["SOUL_PATH"] = str(workspace / "soul.md")
os.environ["AGENTS_PATH"] = str(workspace / "agents")
original_run = flask.Flask.run
def buddy_run(app, *args, **kwargs):
    app.add_url_rule(
        "/buddy-identity",
        "buddy_identity",
        lambda: flask.jsonify({{
            "schema": {BUDDY_SCHEMA!r},
            "rappid": {rappid!r},
            "identity_nonce": {identity_nonce!r},
        }}),
    )
{index_override}
    return original_run(app, *args, **kwargs)
flask.Flask.run = buddy_run
runpy.run_path({str(brainstem_root / "brainstem.py")!r}, run_name="__main__")
'''


def _custom_ui(name: str, role: str) -> tuple[str, str, str]:
    safe_name = html.escape(name)
    safe_role = html.escape(role)
    js = '''let sessionId=null;const history=[];document.getElementById("chat").addEventListener("submit",async(event)=>{event.preventDefault();const message=document.getElementById("message").value.trim();if(!message)return;const output=document.getElementById("response");output.textContent="Working...";try{const body={schema:"rapp-chat/1.0",message,user_input:message,conversation_history:history.slice(-40)};if(sessionId)body.session_id=sessionId;const response=await fetch("/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});const value=await response.json();const answer=value.response||value.error||"No response";if(value.session_id)sessionId=value.session_id;history.push({role:"user",content:message},{role:"assistant",content:answer});if(history.length>40)history.splice(0,history.length-40);output.textContent=answer;}catch(error){output.textContent=error.message;}});'''
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_name}</title>
<script>(()=>{{const p=new URLSearchParams(location.search).get("scoutTheme");document.documentElement.dataset.theme=p||(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light")}})()</script>
<style>
:root{{color-scheme:light;--cp-bg:#f7f4ef;--cp-bg-elevated:#fcfbf8;--cp-surface:#ffffff;--cp-surface-soft:#f5f5f5;--cp-border:#dedede;--cp-border-strong:#919191;--cp-text:#242424;--cp-text-muted:#5c5c5c;--cp-text-soft:#6f6f6f;--cp-accent:#b11f4b;--cp-accent-hover:#9a1a41;--cp-accent-soft:rgba(177,31,75,.08);--cp-accent-fg:#ffffff;--cp-success:#16a34a;--cp-danger:#dc2626;--cp-warning:#f59e0b;--cp-link:#0078d4;--cp-shadow:0 18px 48px rgba(0,0,0,.12);--cp-overlay:rgba(255,255,255,.8);--cp-panel:rgba(255,255,255,.86);--cp-panel-strong:rgba(255,255,255,.96);--cp-sheen:rgba(255,255,255,.55);--cp-highlight:rgba(177,31,75,.12)}}
html[data-theme=dark]{{color-scheme:dark;--cp-bg:#3d3b3a;--cp-bg-elevated:#343231;--cp-surface:#292929;--cp-surface-soft:#2e2e2e;--cp-border:#474747;--cp-border-strong:#5f5f5f;--cp-text:#dedede;--cp-text-muted:#919191;--cp-text-soft:#b0b0b0;--cp-accent:#fd8ea1;--cp-accent-hover:#fb7b91;--cp-accent-soft:rgba(253,142,161,.14);--cp-accent-fg:#1a1a1a;--cp-success:#4ade80;--cp-danger:#f87171;--cp-warning:#fbbf24;--cp-link:#4da6ff;--cp-shadow:0 18px 48px rgba(0,0,0,.32);--cp-overlay:rgba(41,41,41,.88);--cp-panel:rgba(41,41,41,.72);--cp-panel-strong:rgba(41,41,41,.96);--cp-sheen:rgba(255,255,255,.04);--cp-highlight:rgba(253,142,161,.12)}}
</style>
<link rel="stylesheet" href="/buddy.css">
</head>
<body data-rapplication="{safe_name}">
<header><h1>{safe_name}</h1><p>{safe_role}</p></header>
<main>
<section class="card"><h2>Role workspace</h2><p>{safe_role}</p></section>
<section class="card"><h2>Ask {safe_name}</h2><form id="chat"><textarea id="message" aria-label="Message"></textarea><button data-rapp-action="send">Send</button></form><pre id="response" role="status"></pre></section>
<section class="card"><a href="/?ui=chat" data-rapp-action="default-chat">Use default chat</a></section>
</main><script src="/buddy.js"></script></body></html>'''
    css = '''*{box-sizing:border-box}body{margin:0;background:var(--cp-bg);color:var(--cp-text);font-family:"Segoe UI",Aptos,Calibri,-apple-system,BlinkMacSystemFont,sans-serif}header{padding:24px;background:var(--cp-accent);color:var(--cp-accent-fg)}main{max-width:960px;margin:auto;padding:20px;display:grid;gap:14px}.card{padding:16px;border:1px solid var(--cp-border);border-radius:16px;background:var(--cp-surface);box-shadow:var(--cp-shadow)}textarea{width:100%;min-height:110px;padding:10px;color:var(--cp-text);background:var(--cp-surface);border:1px solid var(--cp-border-strong);border-radius:10px}button,a{display:inline-block;margin-top:8px;padding:8px 12px;border:1px solid var(--cp-accent);border-radius:10px;color:var(--cp-accent);background:var(--cp-surface)}pre{white-space:pre-wrap;color:var(--cp-text-muted)}'''
    return page, css, js


def create_buddy(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != BUDDY_SCHEMA:
        raise RappHerdrError(f"buddy payload must use {BUDDY_SCHEMA!r}")
    device_id = _required_text(value.get("device_id"), "buddy.device_id", 64)
    if not _SAFE_ID.fullmatch(device_id):
        raise RappHerdrError("buddy.device_id is unsafe")
    owner = _required_text(value.get("owner"), "buddy.owner", 39)
    if not _OWNER.fullmatch(owner):
        raise RappHerdrError("buddy.owner is not a canonical RAPP/1 owner")
    name = _manifest_text(value.get("name"), "buddy.name", 80)
    role = _required_text(value.get("role"), "buddy.role")
    slug = _slug(name)
    selected_ui = _ui_mode(str(value.get("ui") or "auto"), role)
    port_start = value.get("port_start", 7200)
    if not isinstance(port_start, int):
        raise RappHerdrError("buddy.port_start must be an integer")
    port = _select_port(port_start)
    inventory_root = Path(
        _required_text(value.get("inventory_root"), "buddy.inventory_root")
    ).expanduser().resolve()
    neighborhood_root = Path(
        _required_text(value.get("neighborhood_root"), "buddy.neighborhood_root")
    ).expanduser().resolve()
    brainstem_root = Path(
        _required_text(value.get("brainstem_root"), "buddy.brainstem_root")
    ).expanduser().resolve()
    if not (brainstem_root / "brainstem.py").is_file():
        raise RappHerdrError("device Brainstem source is unavailable")

    rappid = _mint_rappid(owner, slug)
    tail = rappid.rsplit(":", 1)[1]
    workspace = (inventory_root / f"buddy-{slug}-{tail[:8]}").resolve()
    neighborhood = (neighborhood_root / f"{slug}-{tail[:8]}").resolve()
    if workspace.parent != inventory_root or neighborhood.parent != neighborhood_root:
        raise RappHerdrError("buddy paths escape their configured roots")
    if workspace.exists() or neighborhood.exists():
        raise RappHerdrError("refusing to replace an existing buddy path")
    inventory_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    neighborhood_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace_build = Path(
        tempfile.mkdtemp(dir=inventory_root, prefix=".buddy-stage-")
    )
    neighborhood_build = Path(
        tempfile.mkdtemp(dir=neighborhood_root, prefix=".buddy-stage-")
    )
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    identity = {
        "schema": "rapp/1",
        "rappid": rappid,
        "kind": "twin",
        "name": slug,
        "display_name": name,
        "description": role,
        "created_at": created_at,
        "ui": selected_ui,
    }
    identity_nonce = secrets.token_urlsafe(32)
    marker_value = {
        "schema": BUDDY_SCHEMA,
        "rappid": rappid,
        "device_id": device_id,
        "identity_nonce": identity_nonce,
    }
    workspace_committed = False
    neighborhood_committed = False
    try:
        _write_json(
            workspace_build / ".rapp-herdr-buddy.json",
            marker_value,
        )
        _write_json(
            neighborhood_build / ".rapp-herdr-buddy.json",
            marker_value,
        )
        _write_json(workspace_build / "rappid.json", identity)
        _write_text(
            workspace_build / "soul.md",
            (
                f"# {name}\n\n"
                f"You are a device-local rapplication Twin.\n\n"
                f"## Role\n\n{role}\n\n"
                "Use `/chat` as the canonical wire. Be explicit about uncertainty. "
                "Never claim an external action you did not perform.\n"
            ),
        )
        agent_source = _role_agent(name, role)
        _write_text(workspace_build / "agent.py", agent_source)
        _write_text(
            workspace_build / "agents" / "buddy_role_agent.py",
            agent_source,
        )
        _write_text(
            workspace_build / "brainstem.py",
            _wrapper(
                workspace,
                brainstem_root,
                selected_ui == "rapplication",
                rappid,
                identity_nonce,
            ),
        )
        _write_text(
            workspace_build / "requirements.txt",
            "flask\nrequests\npython-dotenv\n",
            0o644,
        )
        if selected_ui == "rapplication":
            page, css, script = _custom_ui(name, role)
            _write_text(workspace_build / "ui" / "index.html", page, 0o644)
            _write_text(workspace_build / "ui" / "styles.css", css, 0o644)
            _write_text(workspace_build / "ui" / "ui.js", script, 0o644)
        _write_json(
            workspace_build / "rapplication.json",
            {
                "schema": "rapp-application/1.0",
                "name": slug,
                "display_name": name,
                "role": role,
                "ui": {
                    "mode": selected_ui,
                    "default_chat_fallback": True,
                },
            },
        )
        neighborhood_rappid = _mint_rappid(owner, f"{slug}-neighborhood")
        _write_json(
            neighborhood_build / "neighborhood.json",
            {
                "schema": "rapp-neighborhood/1.0",
                "name": slug,
                "display_name": f"{name} Neighborhood",
                "neighborhood_rappid": neighborhood_rappid,
                "members_path": "members.json",
            },
        )
        _write_json(
            neighborhood_build / "members.json",
            {
                "schema": "rapp-neighborhood-members/1.0",
                "neighborhood_rappid": neighborhood_rappid,
                "members": [{"rappid": rappid, "role": "buddy"}],
            },
        )
        os.replace(workspace_build, workspace)
        workspace_committed = True
        os.replace(neighborhood_build, neighborhood)
        neighborhood_committed = True
    except BaseException:
        if workspace_build.exists():
            shutil.rmtree(workspace_build)
        if neighborhood_build.exists():
            shutil.rmtree(neighborhood_build)
        if workspace_committed and workspace.exists():
            shutil.rmtree(workspace)
        if neighborhood_committed and neighborhood.exists():
            shutil.rmtree(neighborhood)
        raise
    manifest = neighborhood / "neighborhood.json"
    return {
        "ok": True,
        "schema": BUDDY_SCHEMA,
        "device": device_id,
        "name": name,
        "role": role,
        "rappid": rappid,
        "workspace": str(workspace),
        "manifest": str(manifest),
        "port": port,
        "identity_nonce": identity_nonce,
        "ui": selected_ui,
        "neighborhood": {
            "manifest": str(manifest),
            "estate_roots": [str(inventory_root)],
            "base_port": port,
            "brainstem_python": (
                "~/.brainstem/venv/Scripts/python.exe"
                if os.name == "nt"
                else "~/.brainstem/venv/bin/python"
            ),
            "bootstrap": False,
            "listen_host": "127.0.0.1",
            "entrypoint": "brainstem.py",
            "managed_by": BUDDY_SCHEMA,
            "buddy": {
                "name": name,
                "rappid": rappid,
                "ui": selected_ui,
            },
        },
    }


def run_buddy_device(action: str, value: dict[str, Any]) -> dict[str, Any]:
    if action == "create":
        return create_buddy(value)
    if action == "handshake":
        name = _required_text(value.get("name"), "buddy.name", 80)
        rappid = _required_text(value.get("rappid"), "buddy.rappid", 240)
        identity_nonce = _required_text(
            value.get("identity_nonce"),
            "buddy.identity_nonce",
            200,
        )
        port = value.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise RappHerdrError("buddy.port must be an integer from 1 to 65535")
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/buddy-identity",
                timeout=10,
            ) as response:
                identity = json.loads(response.read())
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health",
                timeout=10,
            ) as response:
                health = json.loads(response.read())
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/chat",
                data=json.dumps(
                    {
                        "schema": "rapp-chat/1.0",
                        "message": (
                            "Introduce yourself by name and role, then end "
                            "with the exact word READY."
                        ),
                        "user_input": (
                            "Introduce yourself by name and role, then end "
                            "with the exact word READY."
                        ),
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=180) as response:
                chat = json.loads(response.read())
        except (
            OSError,
            urllib.error.URLError,
            json.JSONDecodeError,
        ) as exc:
            raise RappHerdrError(f"buddy handshake failed: {type(exc).__name__}") from exc
        text = chat.get("response") if isinstance(chat, dict) else None
        if (
            not isinstance(health, dict)
            or health.get("status") not in {"ok", "ready"}
            or not isinstance(identity, dict)
            or identity.get("schema") != BUDDY_SCHEMA
            or identity.get("rappid") != rappid
            or identity.get("identity_nonce") != identity_nonce
            or not _ready_response(text)
        ):
            raise RappHerdrError("buddy did not complete health and chat handshake")
        return {
            "ok": True,
            "schema": BUDDY_SCHEMA,
            "device": value.get("device_id"),
            "name": name,
            "rappid": rappid,
            "port": port,
            "ready": True,
            "response": text,
            "session_id": chat.get("session_id"),
        }
    if action == "delete":
        workspace = Path(
            _required_text(value.get("workspace"), "buddy.workspace")
        ).expanduser().resolve()
        manifest = Path(
            _required_text(value.get("manifest"), "buddy.manifest")
        ).expanduser().resolve()
        expected = {
            "schema": BUDDY_SCHEMA,
            "rappid": _required_text(value.get("rappid"), "buddy.rappid", 240),
            "device_id": _required_text(
                value.get("device_id"),
                "buddy.device_id",
                64,
            ),
            "identity_nonce": _required_text(
                value.get("identity_nonce"),
                "buddy.identity_nonce",
                200,
            ),
        }
        markers = [
            workspace / ".rapp-herdr-buddy.json",
            manifest.parent / ".rapp-herdr-buddy.json",
        ]
        for marker in markers:
            try:
                actual = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise RappHerdrError(
                    f"cannot prove buddy cleanup ownership: {marker}"
                ) from exc
            if actual != expected:
                raise RappHerdrError(
                    f"buddy cleanup ownership diverged: {marker}"
                )
        shutil.rmtree(workspace)
        shutil.rmtree(manifest.parent)
        return {
            "ok": True,
            "schema": BUDDY_SCHEMA,
            "device": expected["device_id"],
            "rappid": expected["rappid"],
            "deleted": True,
        }
    if action == "chat":
        device_id = _required_text(
            value.get("device_id"),
            "buddy.device_id",
            64,
        )
        url = _required_text(value.get("url"), "buddy.url", 240).rstrip("/")
        parsed = urllib.parse.urlparse(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.port is None
            or parsed.path not in {"", "/"}
        ):
            raise RappHerdrError("buddy chat URL must be loopback HTTP")
        message = _required_text(value.get("message"), "buddy.message", 8_000)
        body = {
            "schema": "rapp-chat/1.0",
            "message": message,
            "user_input": message,
        }
        if isinstance(value.get("session_id"), str) and value["session_id"]:
            body["session_id"] = value["session_id"][:240]
        request = urllib.request.Request(
            url + "/chat",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                chat = json.loads(response.read())
        except (
            OSError,
            urllib.error.URLError,
            json.JSONDecodeError,
        ) as exc:
            raise RappHerdrError(
                f"buddy chat failed: {type(exc).__name__}"
            ) from exc
        text = (
            chat.get("response")
            or chat.get("content")
            or chat.get("assistant_response")
            if isinstance(chat, dict)
            else None
        )
        if not isinstance(text, str) or not text.strip():
            raise RappHerdrError("buddy chat returned no response")
        return {
            "ok": True,
            "schema": BUDDY_SCHEMA,
            "device": device_id,
            "response": text.strip(),
            "session_id": chat.get("session_id"),
            "responded_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
        }
    raise RappHerdrError(f"unsupported buddy action: {action}")


def add_buddy_neighborhood(
    estate_manifest: str | Path,
    device_id: str,
    neighborhood: dict[str, Any],
    *,
    expected_hash: str,
) -> dict[str, Any]:
    manifest = Path(estate_manifest).expanduser().resolve()
    try:
        current_bytes = manifest.read_bytes()
    except OSError as exc:
        raise RappHerdrError(f"cannot update estate manifest {manifest}: {exc}") from exc
    try:
        value = json.loads(current_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot update estate manifest {manifest}: {exc}") from exc
    current_hash = hashlib.sha256(current_bytes).hexdigest()
    if current_hash != expected_hash:
        raise RappHerdrError("estate manifest changed before buddy registration")
    devices = value.get("devices") if isinstance(value, dict) else None
    if not isinstance(devices, list):
        raise RappHerdrError("estate manifest has no device array")
    matches = [
        device for device in devices
        if isinstance(device, dict) and device.get("id") == device_id
    ]
    if len(matches) != 1:
        raise RappHerdrError(f"estate device {device_id!r} is not unique")
    target = matches[0]
    neighborhoods = target.setdefault("neighborhoods", [])
    if not isinstance(neighborhoods, list):
        raise RappHerdrError(f"estate device {device_id!r} has invalid neighborhoods")
    manifest_value = _required_text(
        neighborhood.get("manifest"),
        "buddy.neighborhood.manifest",
    )
    if any(
        isinstance(existing, dict)
        and existing.get("manifest") == manifest_value
        for existing in neighborhoods
    ):
        raise RappHerdrError("buddy neighborhood is already registered")
    registered = dict(neighborhood)
    registered["managed_by"] = BUDDY_SCHEMA
    neighborhoods.append(registered)
    from .backup import replace_estate_manifest

    replaced = replace_estate_manifest(
        manifest,
        value,
        expected_hash=current_hash,
    )
    manifest_hash_after = hashlib.sha256(manifest.read_bytes()).hexdigest()
    return {
        "ok": True,
        "device": device_id,
        "neighborhood": registered,
        "previous_manifest": replaced["previous_manifest"],
        "manifest_hash_before": current_hash,
        "manifest_hash_after": manifest_hash_after,
    }


def remove_buddy_neighborhood(
    estate_manifest: str | Path,
    device_id: str,
    buddy_manifest: str,
    *,
    expected_hash: str,
) -> dict[str, Any]:
    manifest = Path(estate_manifest).expanduser().resolve()
    current_bytes = manifest.read_bytes()
    if hashlib.sha256(current_bytes).hexdigest() != expected_hash:
        raise RappHerdrError(
            "estate manifest changed after buddy registration; "
            "refusing destructive rollback"
        )
    try:
        value = json.loads(current_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot roll back estate manifest {manifest}: {exc}") from exc
    devices = value.get("devices") if isinstance(value, dict) else None
    if not isinstance(devices, list):
        raise RappHerdrError("estate manifest has no device array")
    matches = [
        device for device in devices
        if isinstance(device, dict) and device.get("id") == device_id
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("neighborhoods"), list):
        raise RappHerdrError("buddy rollback device is invalid")
    neighborhoods = matches[0]["neighborhoods"]
    owned = [
        item for item in neighborhoods
        if isinstance(item, dict)
        and item.get("manifest") == buddy_manifest
        and item.get("managed_by") == BUDDY_SCHEMA
    ]
    if len(owned) != 1:
        raise RappHerdrError("buddy rollback ownership could not be proven")
    neighborhoods.remove(owned[0])
    from .backup import replace_estate_manifest

    replace_estate_manifest(
        manifest,
        value,
        expected_hash=expected_hash,
    )
    return {"ok": True, "device": device_id, "removed": buddy_manifest}
