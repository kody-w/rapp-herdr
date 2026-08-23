from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

from .lifecycle import HerdrReporter
from .model import RappHerdrError


def supervise(
    *,
    workspace: Path,
    python: Path,
    port: int,
    name: str,
    rappid: str,
    neighborhood: str,
    listen_host: str,
    entrypoint: str,
    launch_nonce: str,
    herdr_binary: str,
) -> int:
    reporter = HerdrReporter(
        workspace=workspace,
        rappid=rappid,
        twin_name=name,
        neighborhood_name=neighborhood,
        port=port,
        binary=herdr_binary,
    )
    reporter.start(strict=True)

    source_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    existing_python_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(source_root)
        if not existing_python_path
        else os.pathsep.join([str(source_root), existing_python_path])
    )
    command = [
        str(python),
        "-m",
        "rapp_herdr.bootstrap",
        "--workspace",
        str(workspace),
        "--port",
        str(port),
        "--name",
        name,
        "--rappid",
        rappid,
        "--neighborhood",
        neighborhood,
        "--listen-host",
        listen_host,
        "--entrypoint",
        entrypoint,
        "--launch-nonce",
        launch_nonce,
        "--herdr",
        herdr_binary,
    ]
    try:
        child = subprocess.Popen(command, cwd=workspace, env=environment)
    except OSError as exc:
        reporter.state("blocked", f"cannot start Twin brainstem: {exc}")
        reporter.release()
        raise RappHerdrError(f"cannot start Twin brainstem: {exc}") from exc

    previous_handlers: dict[int, object] = {}

    def forward(signum, _frame) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, signal_name, None)
        if signum is None:
            continue
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, forward)
    try:
        return_code = child.wait()
        if return_code != 0:
            reporter.state("blocked", f"Twin brainstem exited with code {return_code}")
        return return_code
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        reporter.release()
