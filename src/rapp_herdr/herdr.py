from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import RappHerdrError

MINIMUM_VERSION = (0, 7, 4)


@dataclass(frozen=True)
class HerdrContext:
    version: tuple[int, int, int]
    socket_path: str


@dataclass(frozen=True)
class HerdrPane:
    workspace_id: str
    tab_id: str
    pane_id: str
    terminal_id: str


class HerdrClient:
    def __init__(
        self,
        *,
        binary: str | None = None,
        session: str | None = None,
        timeout: float = 20.0,
    ):
        candidate = binary or os.environ.get("HERDR_BIN_PATH")
        if candidate:
            expanded = Path(candidate).expanduser()
            has_path_separator = "/" in candidate or "\\" in candidate
            selected = (
                str(expanded.resolve())
                if expanded.is_absolute() or has_path_separator
                else shutil.which(candidate)
            )
        else:
            selected = shutil.which("herdr")
        if not selected:
            raise RappHerdrError("herdr is not installed or not available on PATH")
        self.binary = str(Path(selected).expanduser().resolve())
        self.session = session
        self.timeout = timeout

    def _prefix(self) -> list[str]:
        command = [self.binary]
        if self.session:
            command.extend(["--session", self.session])
        return command

    def _run(self, *args: str, expect_json: bool = True) -> Any:
        command = [*self._prefix(), *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RappHerdrError(f"Herdr command failed: {command!r}: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RappHerdrError(
                f"Herdr command exited {result.returncode}: {' '.join(command)}"
                + (f": {detail}" if detail else "")
            )
        if not expect_json:
            return result.stdout
        output = result.stdout.strip()
        if not output:
            return {}
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise RappHerdrError(
                f"Herdr returned non-JSON output for {' '.join(command)}: {output}"
            ) from exc

    def context(self) -> HerdrContext:
        output = self._run("status", expect_json=False)
        section = ""
        values: dict[tuple[str, str], str] = {}
        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if line and not line.startswith(" ") and line.endswith(":"):
                section = line[:-1]
                continue
            match = re.match(r"^\s{2}([^:]+):\s*(.*)$", line)
            if match:
                values[(section, match.group(1).strip())] = match.group(2).strip()
        if values.get(("server", "status")) != "running":
            raise RappHerdrError(
                "Herdr server is not running; launch or attach to a Herdr session first"
            )
        version_text = values.get(("server", "version")) or values.get(("client", "version"))
        if not version_text:
            raise RappHerdrError("Herdr status did not report a server version")
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version_text)
        if not match:
            raise RappHerdrError(f"cannot parse Herdr version {version_text!r}")
        version = tuple(int(part) for part in match.groups())
        if version < MINIMUM_VERSION:
            required = ".".join(str(part) for part in MINIMUM_VERSION)
            raise RappHerdrError(
                f"Herdr {required}+ is required; server reports {version_text}"
            )
        if values.get(("server", "compatible")) == "no":
            raise RappHerdrError("Herdr client and server protocols are incompatible")
        socket_path = (
            values.get(("server", "socket"))
            or os.environ.get("HERDR_SOCKET_PATH")
            or ""
        )
        if not socket_path:
            raise RappHerdrError("Herdr status did not report its session socket")
        return HerdrContext(version=version, socket_path=socket_path)

    @staticmethod
    def _required(result: Any, path: tuple[str, ...], label: str) -> str:
        value = result
        for key in path:
            if not isinstance(value, dict) or key not in value:
                raise RappHerdrError(f"Herdr response did not include {label}")
            value = value[key]
        if not isinstance(value, str) or not value:
            raise RappHerdrError(f"Herdr response included an invalid {label}")
        return value

    def create_workspace(self, cwd: Path, label: str) -> HerdrPane:
        response = self._run(
            "workspace",
            "create",
            "--cwd",
            str(cwd),
            "--label",
            label,
            "--no-focus",
        )
        return HerdrPane(
            workspace_id=self._required(
                response, ("result", "workspace", "workspace_id"), "workspace_id"
            ),
            tab_id=self._required(
                response, ("result", "root_pane", "tab_id"), "root tab_id"
            ),
            pane_id=self._required(
                response, ("result", "root_pane", "pane_id"), "root pane_id"
            ),
            terminal_id=self._required(
                response, ("result", "root_pane", "terminal_id"), "root terminal_id"
            ),
        )

    def rename_tab(self, tab_id: str, label: str) -> None:
        self._run("tab", "rename", tab_id, label)

    def create_tab(self, workspace_id: str, cwd: Path, label: str) -> HerdrPane:
        response = self._run(
            "tab",
            "create",
            "--workspace",
            workspace_id,
            "--cwd",
            str(cwd),
            "--label",
            label,
            "--no-focus",
        )
        return HerdrPane(
            workspace_id=self._required(
                response, ("result", "root_pane", "workspace_id"), "workspace_id"
            ),
            tab_id=self._required(
                response, ("result", "root_pane", "tab_id"), "tab_id"
            ),
            pane_id=self._required(
                response, ("result", "root_pane", "pane_id"), "pane_id"
            ),
            terminal_id=self._required(
                response, ("result", "root_pane", "terminal_id"), "terminal_id"
            ),
        )

    def run_pane(self, pane_id: str, command: str) -> None:
        self._run("pane", "run", pane_id, command)

    def pane(self, pane_id: str) -> dict[str, Any]:
        response = self._run("pane", "get", pane_id)
        value = response.get("result", {}).get("pane")
        if not isinstance(value, dict):
            raise RappHerdrError(f"Herdr pane {pane_id!r} was not found")
        return value

    def read_pane(self, pane_id: str, lines: int = 80) -> str:
        return self._run(
            "pane",
            "read",
            pane_id,
            "--source",
            "recent-unwrapped",
            "--lines",
            str(lines),
            "--format",
            "text",
            expect_json=False,
        )

    def panes(self, workspace_id: str) -> tuple[dict[str, Any], ...]:
        response = self._run("pane", "list", "--workspace", workspace_id)
        values = response.get("result", {}).get("panes")
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise RappHerdrError("Herdr pane list returned an invalid response")
        return tuple(values)

    def workspaces(self) -> tuple[dict[str, Any], ...]:
        response = self._run("workspace", "list")
        values = response.get("result", {}).get("workspaces")
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise RappHerdrError("Herdr workspace list returned an invalid response")
        return tuple(values)

    def close_workspace(self, workspace_id: str) -> None:
        self._run("workspace", "close", workspace_id)
