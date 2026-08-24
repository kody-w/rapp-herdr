from __future__ import annotations

import base64
import importlib.util
import inspect
import json
import signal
import sys
import re
from pathlib import Path
from typing import Any

from .lifecycle import HerdrReporter
from .model import RappHerdrError

CELL_PAYLOAD_SCHEMA = "rapp-herdr-cell/1.0"


def encode_cell_payload(payload: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()


def decode_cell_payload(encoded: str) -> dict[str, Any]:
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded).decode())
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid neighborhood worker payload: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError("neighborhood worker payload must contain an object")
    return value


def load_cell_payload(path: str | Path) -> dict[str, Any]:
    payload_path = Path(path).expanduser().resolve()
    try:
        value = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"invalid neighborhood worker payload file: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != CELL_PAYLOAD_SCHEMA:
        raise RappHerdrError("unsupported neighborhood worker payload file")
    return value


def _load_module(path: Path):
    module_name = "rapp_herdr_cell_" + path.parent.name.replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RappHerdrError(f"cannot load neighborhood agent: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _invoke(path: Path, prompt: str) -> str:
    module = _load_module(path)
    perform_root = getattr(module, "perform_root", None)
    if callable(perform_root):
        result = perform_root(prompt)
    else:
        candidates = [
            value
            for value in vars(module).values()
            if inspect.isclass(value)
            and value.__module__ == module.__name__
            and callable(getattr(value, "perform", None))
        ]
        if not candidates:
            raise RappHerdrError(f"agent exposes no perform entrypoint: {path}")
        instance = candidates[0]()
        result = instance.perform(input=prompt)
    if isinstance(result, dict):
        response = result.get("response")
        return response if isinstance(response, str) else json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    return str(result)


def _route_prompt(agents: dict[str, Path], prompt: str) -> str:
    words = {
        word
        for word in re.split(r"[^a-z0-9]+", prompt.casefold())
        if word
    }
    scored = []
    for name in sorted(agents):
        route_words = {
            word
            for word in re.split(r"[^a-z0-9]+", name.casefold())
            if word and word not in {"factory", "agent"}
        }
        scored.append((len(words & route_words), name))
    best_score, best_name = max(scored)
    return best_name if best_score > 0 else sorted(agents)[0]


def run_cell(payload: dict[str, Any]) -> int:
    workspace = Path(str(payload.get("workspace", ""))).expanduser().resolve()
    if not workspace.is_dir():
        raise RappHerdrError(f"neighborhood workspace does not exist: {workspace}")
    raw_agents = payload.get("agents")
    if not isinstance(raw_agents, dict) or not raw_agents:
        raise RappHerdrError("neighborhood worker has no runnable agents")
    agents: dict[str, Path] = {}
    for name, raw_path in raw_agents.items():
        if not isinstance(name, str) or not isinstance(raw_path, str):
            raise RappHerdrError("neighborhood worker agents must map names to paths")
        path = Path(raw_path).expanduser().resolve()
        if path != workspace and workspace not in path.parents:
            raise RappHerdrError(f"agent escapes neighborhood workspace: {path}")
        if not path.is_file() or path.suffix != ".py":
            raise RappHerdrError(f"agent is not a Python file: {path}")
        agents[name] = path
    default_agent = payload.get("default_agent")
    if (
        default_agent is not None
        and default_agent != "__router__"
        and default_agent not in agents
    ):
        raise RappHerdrError("default neighborhood agent is not in the agent map")
    label = str(payload.get("label") or workspace.name)
    estate = str(payload.get("estate") or "RAPP Estate")
    session_id = str(payload.get("session_id") or f"rapp-herdr-cell:{workspace}")
    herdr_binary = str(payload.get("herdr_bin") or "herdr")
    reporter = HerdrReporter(
        workspace=workspace,
        rappid=session_id,
        twin_name=label,
        neighborhood_name=label,
        port=None,
        binary=herdr_binary,
        agent="rapp-neighborhood",
        display_agent="RAPP Neighborhood",
        tokens={
            "estate": estate,
            "factories": str(len(agents)),
        },
    )
    reporter.start(strict=True)
    reporter.state("idle", "ready")

    def stop(_signum, _frame) -> None:
        raise KeyboardInterrupt

    previous_handlers: dict[int, object] = {}
    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, signal_name, None)
        if signum is None:
            continue
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, stop)

    names = ", ".join(sorted(agents))
    print(f"[rapp-herdr] {estate} / {label}", flush=True)
    print(f"[rapp-herdr] routes: {names}", flush=True)
    print(
        "[rapp-herdr] send plain text"
        + (f" (default: {default_agent})" if default_agent else " as route: prompt")
        + "; /list; /quit",
        flush=True,
    )
    try:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            if line == "/quit":
                return 0
            if line == "/list":
                print(names, flush=True)
                continue
            route = default_agent
            prompt = line
            if ":" in line:
                prefix, remainder = line.split(":", 1)
                if prefix.strip() in agents:
                    route = prefix.strip()
                    prompt = remainder.strip()
            if route is None:
                print(
                    f"Choose a route first: {names}. Example: {next(iter(agents))}: {line}",
                    flush=True,
                )
                continue
            if route == "__router__":
                route = _route_prompt(agents, prompt)
                print(f"[rapp-herdr] routed -> {route}", flush=True)
            reporter.state("working", f"running {route}")
            try:
                output = _invoke(agents[route], prompt)
            except Exception as exc:
                reporter.state("blocked", f"{route} failed: {type(exc).__name__}")
                print(f"[rapp-herdr] {route} failed: {exc}", flush=True)
                continue
            print(output, flush=True)
            reporter.state("idle", "ready")
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        reporter.release()
