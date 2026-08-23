from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .model import RappHerdrError

LAUNCH_HEADER = "X-RAPP-Herdr-Launch"


class HerdrReporter:
    def __init__(
        self,
        *,
        workspace: Path,
        rappid: str,
        twin_name: str,
        neighborhood_name: str,
        port: int | None,
        binary: str | None = None,
        agent: str = "rapp-twin",
        display_agent: str = "RAPP Twin",
        tokens: dict[str, str] | None = None,
    ):
        self.workspace = workspace.resolve()
        self.rappid = rappid
        self.twin_name = twin_name
        self.neighborhood_name = neighborhood_name
        self.port = port
        self.agent = agent
        self.display_agent = display_agent
        self.extra_tokens = dict(tokens or {})
        self.binary = binary or os.environ.get("HERDR_BIN_PATH") or shutil.which("herdr")
        self.pane_id = os.environ.get("HERDR_PANE_ID")
        source_hash = hashlib.sha256(
            f"{self.agent}\0{self.workspace}".encode()
        ).hexdigest()[:16]
        self.source = f"rapp-herdr:{self.agent}:{source_hash}"
        self.metadata_source = f"{self.source}:metadata"
        self._sequence = 0
        self._lock = threading.Lock()
        self._released = False
        self._last_state: tuple[str, str] | None = None

    def _next_sequence(self) -> int:
        with self._lock:
            now = time.time_ns()
            self._sequence = max(now, self._sequence + 1)
            return self._sequence

    def reserve_sequence(self) -> int:
        return self._next_sequence()

    def _command(self, *args: str, strict: bool = False) -> bool:
        if os.environ.get("HERDR_ENV") != "1" or not self.binary or not self.pane_id:
            if strict:
                raise RappHerdrError(
                    "Twin supervisor must run inside a Herdr pane with the "
                    "RAPP-Herdr lifecycle environment"
                )
            return False
        command = [self.binary, "pane", *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            if strict:
                raise RappHerdrError(f"cannot report Twin state to Herdr: {exc}") from exc
            print(f"[rapp-herdr] lifecycle report failed: {exc}", flush=True)
            return False
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            if strict:
                raise RappHerdrError(
                    f"Herdr rejected Twin lifecycle report: {detail or result.returncode}"
                )
            print(
                f"[rapp-herdr] lifecycle report rejected: "
                f"{detail or result.returncode}",
                flush=True,
            )
            return False
        return True

    def start(self, *, strict: bool = False) -> None:
        sequence = self._next_sequence()
        self._command(
            "report-agent-session",
            self.pane_id or "",
            "--source",
            self.source,
            "--agent",
            self.agent,
            "--seq",
            str(sequence),
            "--agent-session-id",
            self.rappid,
            "--agent-session-path",
            str(self.workspace),
            strict=strict,
        )
        metadata_args = [
            "report-metadata",
            self.pane_id or "",
            "--source",
            self.metadata_source,
            "--agent",
            self.agent,
            "--applies-to-source",
            self.source,
            "--title",
            self.twin_name[:120],
            "--display-agent",
            self.display_agent,
            "--state-label",
            "idle=Ready",
            "--state-label",
            "working=Thinking",
            "--state-label",
            "blocked=Blocked",
        ]
        token_values = {
            "neighborhood": self.neighborhood_name[:120],
            **self.extra_tokens,
        }
        if self.port is not None:
            token_values["port"] = str(self.port)
            token_values["endpoint"] = f"http://127.0.0.1:{self.port}"
        for name, value in sorted(token_values.items()):
            metadata_args.extend(["--token", f"{name}={value[:500]}"])
        metadata_args.extend(["--seq", str(self._next_sequence())])
        self._command(*metadata_args, strict=strict)
        self.state("working", "starting Twin brainstem", strict=strict)

    def state(
        self,
        state: str,
        message: str = "",
        *,
        strict: bool = False,
        sequence: int | None = None,
    ) -> None:
        if state not in {"idle", "working", "blocked", "unknown"}:
            raise ValueError(f"unsupported Herdr state: {state}")
        if sequence is None:
            current = (state, message)
            with self._lock:
                if self._last_state == current and not strict:
                    return
                self._last_state = current
            sequence = self._next_sequence()
        args = [
            "report-agent",
            self.pane_id or "",
            "--source",
            self.source,
            "--agent",
            self.agent,
            "--state",
            state,
            "--seq",
            str(sequence),
            "--agent-session-id",
            self.rappid,
            "--agent-session-path",
            str(self.workspace),
        ]
        if message:
            args.extend(["--message", message[:500]])
        self._command(*args, strict=strict)

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        clear_args = [
            "report-metadata",
            self.pane_id or "",
            "--source",
            self.metadata_source,
            "--agent",
            self.agent,
            "--applies-to-source",
            self.source,
            "--clear-title",
            "--clear-display-agent",
            "--clear-state-labels",
        ]
        token_names = {"neighborhood", *self.extra_tokens}
        if self.port is not None:
            token_names.update({"port", "endpoint"})
        for name in sorted(token_names):
            clear_args.extend(["--clear-token", name])
        clear_args.extend(["--seq", str(self._next_sequence())])
        self._command(*clear_args)
        self._command(
            "release-agent",
            self.pane_id or "",
            "--source",
            self.source,
            "--agent",
            self.agent,
            "--seq",
            str(self._next_sequence()),
        )


class TwinLifecycle:
    def __init__(self, reporter: HerdrReporter, launch_nonce: str = ""):
        self.reporter = reporter
        self.launch_nonce = launch_nonce
        self._lock = threading.Lock()
        self._active = 0
        self._ready = False
        self._cycle_error: str | None = None

    def install(self, app: Any) -> None:
        if getattr(app, "_rapp_herdr_lifecycle", False):
            return
        setattr(app, "_rapp_herdr_lifecycle", True)
        from flask import g, request

        @app.before_request
        def rapp_herdr_before_request() -> None:
            if request.path.rstrip("/") != "/chat":
                return
            g.rapp_herdr_chat = True
            g.rapp_herdr_status = None
            self.begin_chat()

        @app.after_request
        def rapp_herdr_after_request(response: Any) -> Any:
            if request.path.rstrip("/") == "/health" and self.launch_nonce:
                response.headers[LAUNCH_HEADER] = self.launch_nonce
            if getattr(g, "rapp_herdr_chat", False):
                g.rapp_herdr_status = int(response.status_code)
            return response

        @app.teardown_request
        def rapp_herdr_teardown_request(error: BaseException | None) -> None:
            if not getattr(g, "rapp_herdr_chat", False):
                return
            self.end_chat(getattr(g, "rapp_herdr_status", None), error)

    def begin_chat(self) -> None:
        with self._lock:
            if self._active == 0:
                self._cycle_error = None
            self._active += 1
            sequence = self.reporter.reserve_sequence()
        self.reporter.state(
            "working",
            "processing /chat",
            sequence=sequence,
        )

    def end_chat(
        self,
        status_code: int | None,
        error: BaseException | None = None,
    ) -> None:
        with self._lock:
            if error is not None:
                self._cycle_error = f"/chat raised {type(error).__name__}"
            elif status_code in {401, 403}:
                self._cycle_error = f"/chat requires authentication ({status_code})"
            elif status_code is None or status_code >= 500:
                self._cycle_error = f"/chat failed ({status_code or 'no response'})"
            self._active = max(0, self._active - 1)
            if self._active:
                return
            blocked = self._cycle_error
            ready = self._ready
            sequence = self.reporter.reserve_sequence()
        if blocked:
            self.reporter.state("blocked", blocked, sequence=sequence)
        elif ready:
            self.reporter.state("idle", "ready", sequence=sequence)
        else:
            self.reporter.state(
                "working",
                "starting Twin brainstem",
                sequence=sequence,
            )

    def mark_ready(self) -> None:
        with self._lock:
            self._ready = True
            if self._active:
                return
            sequence = self.reporter.reserve_sequence()
        self.reporter.state("idle", "ready", sequence=sequence)

    def mark_startup_failure(self, message: str) -> None:
        with self._lock:
            self._cycle_error = message
            sequence = self.reporter.reserve_sequence()
        self.reporter.state("blocked", message, sequence=sequence)


def wait_for_health(
    lifecycle: TwinLifecycle,
    *,
    port: int,
    launch_nonce: str,
    timeout: float = 60.0,
) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if (
                    200 <= int(response.status) < 300
                    and response.headers.get(LAUNCH_HEADER) == launch_nonce
                ):
                    lifecycle.mark_ready()
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    lifecycle.mark_startup_failure(f"health check timed out on port {port}")
