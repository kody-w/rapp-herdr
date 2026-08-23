from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
import threading
from pathlib import Path

from .lifecycle import HerdrReporter, TwinLifecycle, wait_for_health
from .model import RappHerdrError
from .probe import (
    PROBE_NEIGHBORHOOD_NAME,
    PROBE_SCHEMA,
    probe_rappid,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--rappid", required=True)
    parser.add_argument("--neighborhood", required=True)
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--launch-nonce", required=True)
    parser.add_argument("--herdr", required=True)
    return parser


def _entrypoint(workspace: Path, raw: str) -> Path:
    relative = Path(raw)
    if relative.is_absolute():
        raise RappHerdrError("Twin entrypoint must be relative to its workspace")
    entrypoint = (workspace / relative).resolve()
    if entrypoint != workspace and workspace not in entrypoint.parents:
        raise RappHerdrError("Twin entrypoint escapes its workspace")
    if entrypoint.suffix != ".py" or not entrypoint.is_file():
        raise RappHerdrError(f"Twin entrypoint is not a Python file: {entrypoint}")
    return entrypoint


def _is_persistence_probe(
    workspace: Path,
    *,
    rappid: str,
    neighborhood: str,
    entrypoint: str,
) -> bool:
    marker = workspace / ".rapp-herdr-probe.json"
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    device_id = value.get("device_id") if isinstance(value, dict) else None
    return (
        isinstance(device_id, str)
        and value.get("schema") == PROBE_SCHEMA
        and value.get("rappid") == rappid
        and rappid == probe_rappid(device_id)
        and workspace.name == f"rapp-herdr-persistence-probe-{device_id}"
        and neighborhood == PROBE_NEIGHBORHOOD_NAME
        and entrypoint == "brainstem.py"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    if not (workspace / "brainstem.py").is_file():
        raise RappHerdrError(f"Twin workspace is missing brainstem.py: {workspace}")

    os.chdir(workspace)
    os.environ["PORT"] = str(args.port)
    os.environ["SOUL_PATH"] = str(workspace / "soul.md")
    os.environ["AGENTS_PATH"] = str(workspace / "agents")
    os.environ["PYTHONUTF8"] = "1"
    os.environ["RAPP_HERDR_LAUNCH_NONCE"] = args.launch_nonce
    os.environ["RAPP_HERDR_LISTEN_HOST"] = args.listen_host

    reporter = HerdrReporter(
        workspace=workspace,
        rappid=args.rappid,
        twin_name=args.name,
        neighborhood_name=args.neighborhood,
        port=args.port,
        binary=args.herdr,
    )
    reporter.start(strict=True)

    entrypoint = _entrypoint(workspace, args.entrypoint)
    if _is_persistence_probe(
        workspace,
        rappid=args.rappid,
        neighborhood=args.neighborhood,
        entrypoint=args.entrypoint,
    ):
        lifecycle = TwinLifecycle(reporter, args.launch_nonce)
        watcher = threading.Thread(
            target=wait_for_health,
            kwargs={
                "lifecycle": lifecycle,
                "port": args.port,
                "launch_nonce": args.launch_nonce,
            },
            name=f"rapp-herdr-health-{args.port}",
            daemon=True,
        )
        watcher.start()
        try:
            runpy.run_path(str(entrypoint), run_name="__main__")
            return 0
        except KeyboardInterrupt:
            return 130
        except BaseException as fallback_exc:
            reporter.state(
                "blocked",
                f"Twin brainstem exited: {type(fallback_exc).__name__}",
            )
            raise
        finally:
            reporter.release()

    import flask

    original_run = flask.Flask.run

    def instrumented_run(app, *run_args, **run_kwargs):
        lifecycle = TwinLifecycle(reporter, args.launch_nonce)
        lifecycle.install(app)
        watcher = threading.Thread(
            target=wait_for_health,
            kwargs={
                "lifecycle": lifecycle,
                "port": args.port,
                "launch_nonce": args.launch_nonce,
            },
            name=f"rapp-herdr-health-{args.port}",
            daemon=True,
        )
        watcher.start()
        positional = list(run_args)
        if positional:
            positional[0] = args.listen_host
        else:
            run_kwargs["host"] = args.listen_host
        if len(positional) > 1:
            positional[1] = args.port
        else:
            run_kwargs["port"] = args.port
        return original_run(app, *positional, **run_kwargs)

    flask.Flask.run = instrumented_run
    utils = workspace / "utils"
    if str(utils) not in sys.path:
        sys.path.insert(0, str(utils))
    if str(workspace) not in sys.path:
        sys.path.insert(0, str(workspace))
    try:
        runpy.run_path(str(entrypoint), run_name="__main__")
        return 0
    except KeyboardInterrupt:
        return 130
    except BaseException as exc:
        reporter.state("blocked", f"Twin brainstem exited: {type(exc).__name__}")
        raise
    finally:
        reporter.release()


if __name__ == "__main__":
    raise SystemExit(main())
