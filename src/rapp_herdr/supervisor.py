from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from .lifecycle import HerdrReporter
from .model import RappHerdrError


def _bootstrap_artifact() -> Path:
    package = Path(__file__).resolve().parent
    sources = sorted(package.rglob("*.py"))
    digest = hashlib.sha256()
    for source in sources:
        relative = source.relative_to(package)
        digest.update(str(relative).encode())
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    configured_root = os.environ.get("RAPP_HERDR_BOOTSTRAP_ROOT")
    root = (
        Path(configured_root).expanduser()
        if configured_root
        else Path.home() / ".cache" / "rapp-herdr" / "bootstrap"
    )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifact = root / f"rapp-herdr-{digest.hexdigest()}.zip"
    if artifact.is_file():
        return artifact
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{artifact.name}.",
        dir=root,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for source in sources:
                bundle.write(
                    source,
                    arcname=str(Path("rapp_herdr") / source.relative_to(package)),
                )
        os.chmod(temporary, 0o600)
        os.replace(temporary, artifact)
        os.chmod(artifact, 0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return artifact


def _forward_signal(child: subprocess.Popen, signum: int, *, windows: bool) -> None:
    if child.poll() is not None:
        return
    if windows:
        child.terminate()
    else:
        child.send_signal(signum)


def _terminate_and_wait(child: subprocess.Popen) -> None:
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)


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

    bootstrap_artifact = _bootstrap_artifact()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(bootstrap_artifact)
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
    interrupted_by: int | None = None

    def forward(signum, _frame) -> None:
        nonlocal interrupted_by
        interrupted_by = signum
        _forward_signal(child, signum, windows=os.name == "nt")

    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, signal_name, None)
        if signum is None:
            continue
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, forward)
    try:
        try:
            return_code = child.wait()
        except BaseException:
            _terminate_and_wait(child)
            raise
        if return_code != 0:
            reporter.state("blocked", f"Twin brainstem exited with code {return_code}")
        return 128 + interrupted_by if interrupted_by is not None else return_code
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        reporter.release()
