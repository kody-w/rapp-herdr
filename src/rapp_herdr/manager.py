from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import venv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .herdr import HerdrClient, HerdrContext, HerdrPane
from .lifecycle import LAUNCH_HEADER
from .model import Neighborhood, NeighborhoodTopology, RappHerdrError
from .receipts import RECEIPT_SCHEMA, ReceiptStore

_INDEX_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[A-Za-z0-9._,-]+\])?"
    r"(?:\s*(?:===|~=|==|!=|<=|>=|<|>)\s*[^,;\s]+"
    r"(?:\s*,\s*(?:===|~=|==|!=|<=|>=|<|>)\s*[^,;\s]+)*)?"
    r"(?:\s*;\s*.+)?$"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _port_is_available(port: int) -> bool:
    if not 1 <= port <= 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def allocate_ports(count: int, base_port: int) -> tuple[int, ...]:
    ports: list[int] = []
    candidate = base_port
    while len(ports) < count and candidate <= 65535:
        if _port_is_available(candidate):
            ports.append(candidate)
        candidate += 1
    if len(ports) != count:
        raise RappHerdrError(
            f"could not allocate {count} local ports starting at {base_port}"
        )
    return tuple(ports)


def _default_brainstem_python(requirements_fingerprint: str) -> Path:
    configured_root = os.environ.get("RAPP_HERDR_VENV_ROOT")
    root = (
        Path(configured_root).expanduser()
        if configured_root
        else Path.home() / ".cache" / "rapp-herdr" / "venvs"
    )
    environment = root / requirements_fingerprint[:32]
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _runtime_imports_work(python: Path) -> bool:
    result = subprocess.run(
        [str(python), "-c", "import flask, requests, dotenv"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    return result.returncode == 0


def _requirements_satisfied(
    python: Path,
    requirements: Path,
) -> tuple[bool, tuple[str, ...]]:
    result = subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--quiet",
            "--report",
            "-",
            "-r",
            str(requirements),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RappHerdrError(
            f"cannot verify Twin runtime requirements from {requirements}"
            + (f": {detail}" if detail else "")
        )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RappHerdrError(
            f"pip returned an invalid requirements report for {requirements}"
        ) from exc
    installs = report.get("install")
    if not isinstance(installs, list):
        raise RappHerdrError(
            f"pip requirements report omitted its install plan for {requirements}"
        )
    names: list[str] = []
    for item in installs:
        metadata = item.get("metadata") if isinstance(item, dict) else None
        name = metadata.get("name") if isinstance(metadata, dict) else None
        names.append(name if isinstance(name, str) and name else "unknown")
    return not installs, tuple(names)


def _requirements_fingerprint(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RappHerdrError(f"cannot read Twin requirements {path}: {exc}") from exc
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if (
            "@" in line
            or "/" in line
            or "\\" in line
            or line.casefold().endswith(
                (".whl", ".zip", ".tar", ".tar.gz", ".tgz")
            )
            or not _INDEX_REQUIREMENT.fullmatch(line)
        ):
            raise RappHerdrError(
                f"{path}:{line_number}: shared Twin environments require "
                "self-contained index requirement specifiers; includes, "
                "constraints, direct URLs, editable installs, continuations, "
                "and local paths are not supported"
            )
    return hashlib.sha256(content.encode()).hexdigest()


def prepare_brainstem_python(
    topology: NeighborhoodTopology,
    *,
    configured_python: str | Path | None = None,
    bootstrap: bool = True,
) -> Path:
    requirement_files = {
        twin.requirements.resolve()
        for twin in topology.twins
        if twin.requirements is not None
    }
    fingerprints: dict[str, Path] = {}
    for path in requirement_files:
        digest = _requirements_fingerprint(path)
        fingerprints.setdefault(digest, path)
    if len(fingerprints) > 1:
        raise RappHerdrError(
            "local Twins declare different runtime requirements; place only "
            "runtime-compatible Twins in one managed neighborhood"
        )
    requirements_fingerprint = next(iter(fingerprints), "base")
    requirements = next(iter(fingerprints.values()), None)
    if configured_python:
        python = Path(configured_python).expanduser().absolute()
        if not python.is_file():
            raise RappHerdrError(
                f"configured RAPP brainstem Python does not exist: {python}"
            )
    else:
        python = _default_brainstem_python(requirements_fingerprint)

    lock_store = ReceiptStore()
    lock_digest = hashlib.sha256(str(python).encode()).hexdigest()
    lock_path = lock_store.root / "python-locks" / f"{lock_digest}.json"
    with lock_store.operation_lock(lock_path, wait_timeout=300):
        return _prepare_brainstem_python_locked(
            python,
            requirements=requirements,
            bootstrap=bootstrap,
        )


def _prepare_brainstem_python_locked(
    python: Path,
    *,
    requirements: Path | None,
    bootstrap: bool,
) -> Path:
    if not python.is_file():
        if not bootstrap:
            raise RappHerdrError(
                f"RAPP brainstem Python does not exist: {python}; "
                "run a Twin installer or omit --no-bootstrap"
            )
        python.parent.parent.mkdir(parents=True, exist_ok=True)
        try:
            venv.EnvBuilder(with_pip=True).create(python.parent.parent)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RappHerdrError(f"cannot create RAPP brainstem venv: {exc}") from exc
    if requirements is None and _runtime_imports_work(python):
        return python
    if requirements is None:
        raise RappHerdrError(
            "Twin runtime dependencies are missing and no "
            "requirements.txt was found"
        )
    if not bootstrap:
        satisfied, missing = _requirements_satisfied(python, requirements)
        if not satisfied:
            raise RappHerdrError(
                f"{python} does not satisfy {requirements}; missing or "
                f"outdated distributions: {', '.join(missing)}"
            )
        if not _runtime_imports_work(python):
            raise RappHerdrError(
                f"{python} cannot import Flask, requests, or python-dotenv"
            )
        return python
    result = subprocess.run(
        [str(python), "-m", "pip", "install", "-r", str(requirements), "--quiet"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0 or not _runtime_imports_work(python):
        detail = (result.stderr or result.stdout).strip()
        raise RappHerdrError(
            f"cannot install Twin runtime dependencies from {requirements}"
            + (f": {detail}" if detail else "")
        )
    return python


def _shell_command(arguments: list[str]) -> str:
    if os.name == "nt":
        return _powershell_command(arguments)
    return shlex.join(arguments)


def _powershell_command(arguments: list[str]) -> str:
    payload = base64.b64encode(
        json.dumps(
            {
                "executable": arguments[0],
                "arguments": arguments[1:],
            },
            separators=(",", ":"),
        ).encode()
    ).decode("ascii")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}'));"
        "$launch=$json|ConvertFrom-Json;"
        "$exe=[string]$launch.executable;"
        "$launchArgs=@($launch.arguments);"
        "& $exe @launchArgs;"
        "exit $LASTEXITCODE"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return (
        "powershell.exe -NoLogo -NoProfile -NonInteractive "
        f"-EncodedCommand {encoded}"
    )


def _internal_twin_command(
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
) -> str:
    source_root = Path(__file__).resolve().parents[1]
    code = (
        "import sys; "
        "sys.path.insert(0, sys.argv.pop(1)); "
        "from rapp_herdr.cli import main; "
        "raise SystemExit(main(sys.argv[1:]))"
    )
    arguments = [
        sys.executable,
        "-c",
        code,
        str(source_root),
        "_twin",
        "--workspace",
        str(workspace),
        "--python",
        str(python),
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
    return _shell_command(arguments)


class NeighborhoodManager:
    def __init__(self, client: HerdrClient, receipts: ReceiptStore):
        self.client = client
        self.receipts = receipts

    @staticmethod
    def _workspace_label(neighborhood: Neighborhood) -> str:
        return f"RAPP Neighborhood: {neighborhood.name}"[:160]

    def _receipt_path(
        self,
        neighborhood: Neighborhood,
        context: HerdrContext,
    ) -> Path:
        return self.receipts.path_for(neighborhood, context.socket_path)

    def _member_record(
        self,
        twin,
        pane: HerdrPane,
        port: int,
        launch_nonce: str,
    ) -> dict[str, Any]:
        return {
            "name": twin.name,
            "rappid": twin.rappid,
            "workspace": str(twin.workspace),
            "port": port,
            "url": f"http://127.0.0.1:{port}",
            "tab_id": pane.tab_id,
            "pane_id": pane.pane_id,
            "terminal_id": pane.terminal_id,
            "launch_nonce": launch_nonce,
            "requirements_fingerprint": (
                _requirements_fingerprint(twin.requirements)
                if twin.requirements is not None
                else None
            ),
        }

    def _new_receipt(
        self,
        topology: NeighborhoodTopology,
        context: HerdrContext,
        root_pane: HerdrPane,
        members: list[dict[str, Any]],
        state: str,
        operation_token: str,
        *,
        python: Path,
        configured_python: str | Path | None,
        base_port: int,
        listen_host: str,
        entrypoint: str,
    ) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA,
            "state": state,
            "operation_token": operation_token,
            "created_at": _now(),
            "host": platform.node() or socket.gethostname(),
            "neighborhood": {
                "name": topology.neighborhood.name,
                "semantic_id": topology.neighborhood.semantic_id,
                "local_key": topology.neighborhood.local_key,
                "manifest": str(topology.neighborhood.manifest_path),
                "members": str(topology.neighborhood.members_path),
                "unresolved_rappids": list(topology.unresolved_rappids),
            },
            "herdr": {
                "socket": context.socket_path,
                "workspace_id": root_pane.workspace_id,
                "workspace_label": self._workspace_label(topology.neighborhood),
            },
            "launch": {
                "python": str(python),
                "configured_python": (
                    str(Path(configured_python).expanduser().absolute())
                    if configured_python
                    else None
                ),
                "base_port": base_port,
                "listen_host": listen_host,
                "entrypoint": entrypoint,
            },
            "members": members,
        }

    @staticmethod
    def _desired_member_signature(
        topology: NeighborhoodTopology,
    ) -> list[tuple[str, str, str, str | None]]:
        return [
            (
                twin.name,
                twin.rappid,
                str(twin.workspace),
                (
                    _requirements_fingerprint(twin.requirements)
                    if twin.requirements is not None
                    else None
                ),
            )
            for twin in topology.twins
        ]

    def _receipt_matches_request(
        self,
        receipt: dict[str, Any],
        topology: NeighborhoodTopology,
        *,
        base_port: int,
        brainstem_python: str | Path | None,
        listen_host: str,
        entrypoint: str,
    ) -> bool:
        neighborhood = receipt.get("neighborhood")
        launch = receipt.get("launch")
        members = receipt.get("members")
        if (
            not isinstance(neighborhood, dict)
            or not isinstance(launch, dict)
            or not isinstance(members, list)
        ):
            return False
        existing_members = [
            (
                member.get("name"),
                member.get("rappid"),
                member.get("workspace"),
                member.get("requirements_fingerprint"),
            )
            for member in members
            if isinstance(member, dict)
        ]
        configured = (
            str(Path(brainstem_python).expanduser().absolute())
            if brainstem_python
            else None
        )
        return (
            neighborhood.get("name") == topology.neighborhood.name
            and neighborhood.get("semantic_id") == topology.neighborhood.semantic_id
            and neighborhood.get("local_key") == topology.neighborhood.local_key
            and neighborhood.get("unresolved_rappids")
            == list(topology.unresolved_rappids)
            and existing_members == self._desired_member_signature(topology)
            and launch.get("configured_python") == configured
            and launch.get("base_port") == base_port
            and launch.get("listen_host") == listen_host
            and launch.get("entrypoint") == entrypoint
        )

    def _wait_until_ready(
        self,
        pane_id: str,
        port: int,
        launch_nonce: str,
        timeout: float = 60.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        last: dict[str, Any] = {}
        url = f"http://127.0.0.1:{port}"
        while time.monotonic() < deadline:
            last = self.client.pane(pane_id)
            if last.get("agent") == "rapp-twin":
                state = last.get("agent_status")
                if state == "blocked":
                    output = self.client.read_pane(pane_id, lines=100)
                    raise RappHerdrError(
                        f"Twin in pane {pane_id} is blocked"
                        + (f":\n{output}" if output else "")
                    )
                if self._health(url, launch_nonce):
                    return
            time.sleep(0.2)
        output = self.client.read_pane(pane_id, lines=100)
        raise RappHerdrError(
            f"Twin in pane {pane_id} did not pass /health; "
            f"last state={last.get('agent_status', 'unknown')!r}"
            + (f":\n{output}" if output else "")
        )

    def up(
        self,
        topology: NeighborhoodTopology,
        *,
        base_port: int,
        brainstem_python: str | Path | None = None,
        bootstrap: bool = True,
        listen_host: str = "127.0.0.1",
        entrypoint: str = "brainstem.py",
    ) -> dict[str, Any]:
        context = self.client.context()
        receipt_path = self._receipt_path(topology.neighborhood, context)
        with self.receipts.operation_lock(receipt_path) as operation_token:
            return self._up_locked(
                topology,
                context=context,
                receipt_path=receipt_path,
                operation_token=operation_token,
                base_port=base_port,
                brainstem_python=brainstem_python,
                bootstrap=bootstrap,
                listen_host=listen_host,
                entrypoint=entrypoint,
            )

    def _up_locked(
        self,
        topology: NeighborhoodTopology,
        *,
        context: HerdrContext,
        receipt_path: Path,
        operation_token: str,
        base_port: int,
        brainstem_python: str | Path | None,
        bootstrap: bool,
        listen_host: str,
        entrypoint: str,
    ) -> dict[str, Any]:
        existing = self.receipts.load(receipt_path)
        if existing is not None:
            if not self._receipt_matches_request(
                existing,
                topology,
                base_port=base_port,
                brainstem_python=brainstem_python,
                listen_host=listen_host,
                entrypoint=entrypoint,
            ):
                raise RappHerdrError(
                    "managed neighborhood topology or launch configuration "
                    "changed; run neighborhood down, then up"
                )
            status = self._status_receipt(existing)
            if status["managed"]:
                members_by_rappid = {
                    member.get("rappid"): member
                    for member in existing.get("members", [])
                    if isinstance(member, dict)
                }
                twins_by_rappid = {
                    twin.rappid: twin for twin in topology.twins
                }
                launch = existing.get("launch")
                if not isinstance(launch, dict):
                    raise RappHerdrError("managed receipt has no launch configuration")
                python: Path | None = None
                changed = False
                for member_status in status.get("members", []):
                    rappid = member_status.get("rappid")
                    member = members_by_rappid.get(rappid)
                    twin = twins_by_rappid.get(rappid)
                    if member is None or twin is None:
                        raise RappHerdrError(
                            f"managed receipt references unknown Twin {rappid!r}"
                        )
                    if member_status.get("live"):
                        if not member_status.get("healthy"):
                            self._wait_until_ready(
                                str(member["pane_id"]),
                                int(member["port"]),
                                str(member["launch_nonce"]),
                            )
                        continue
                    if python is None:
                        python = Path(
                            str(launch.get("python", ""))
                        ).expanduser().resolve()
                        if not python.is_file():
                            raise RappHerdrError(
                                f"managed Twin interpreter is unavailable: {python}"
                            )
                    launch_nonce = secrets.token_urlsafe(24)
                    member["launch_nonce"] = launch_nonce
                    command = _internal_twin_command(
                        workspace=twin.workspace,
                        python=python,
                        port=int(member["port"]),
                        name=twin.name,
                        rappid=twin.rappid,
                        neighborhood=topology.neighborhood.name,
                        listen_host=listen_host,
                        entrypoint=entrypoint,
                        launch_nonce=launch_nonce,
                        herdr_binary=self.client.binary,
                    )
                    self.client.run_pane(str(member["pane_id"]), command)
                    self._wait_until_ready(
                        str(member["pane_id"]),
                        int(member["port"]),
                        launch_nonce,
                    )
                    changed = True
                if changed:
                    self.receipts.write(receipt_path, existing)
                return self._status_receipt(existing)
            raise RappHerdrError(
                f"stale or divergent receipt at {receipt_path}; "
                "inspect status and run neighborhood down before recreating"
            )

        python = prepare_brainstem_python(
            topology,
            configured_python=brainstem_python,
            bootstrap=bootstrap,
        )
        ports = allocate_ports(len(topology.twins), base_port)
        root_pane: HerdrPane | None = None
        receipt: dict[str, Any] | None = None
        try:
            root_pane = self.client.create_workspace(
                topology.twins[0].workspace,
                self._workspace_label(topology.neighborhood),
            )
            panes = [root_pane]
            self.client.rename_tab(root_pane.tab_id, topology.twins[0].name)
            for twin in topology.twins[1:]:
                panes.append(
                    self.client.create_tab(
                        root_pane.workspace_id,
                        twin.workspace,
                        twin.name,
                    )
                )
            launch_nonces = tuple(
                secrets.token_urlsafe(24) for _ in topology.twins
            )
            members = [
                self._member_record(twin, pane, port, launch_nonce)
                for twin, pane, port, launch_nonce in zip(
                    topology.twins,
                    panes,
                    ports,
                    launch_nonces,
                    strict=True,
                )
            ]
            receipt = self._new_receipt(
                topology,
                context,
                root_pane,
                members,
                "starting",
                operation_token,
                python=python,
                configured_python=brainstem_python,
                base_port=base_port,
                listen_host=listen_host,
                entrypoint=entrypoint,
            )
            self.receipts.write(receipt_path, receipt)

            for twin, pane, port, launch_nonce in zip(
                topology.twins,
                panes,
                ports,
                launch_nonces,
                strict=True,
            ):
                command = _internal_twin_command(
                    workspace=twin.workspace,
                    python=python,
                    port=port,
                    name=twin.name,
                    rappid=twin.rappid,
                    neighborhood=topology.neighborhood.name,
                    listen_host=listen_host,
                    entrypoint=entrypoint,
                    launch_nonce=launch_nonce,
                    herdr_binary=self.client.binary,
                )
                self.client.run_pane(pane.pane_id, command)
                self._wait_until_ready(pane.pane_id, port, launch_nonce)
            receipt["state"] = "running"
            receipt["ready_at"] = _now()
            self.receipts.write(receipt_path, receipt)
            return self._status_receipt(receipt)
        except BaseException as exc:
            rollback_error: Exception | None = None
            if root_pane is not None:
                try:
                    self.client.close_workspace(root_pane.workspace_id)
                except Exception as rollback_exc:
                    rollback_error = rollback_exc
            if rollback_error is None:
                self.receipts.delete_if_token(receipt_path, operation_token)
            elif receipt is not None:
                receipt["state"] = "partial"
                receipt["failure"] = str(exc)
                receipt["rollback_failure"] = str(rollback_error)
                self.receipts.write(receipt_path, receipt)
            if rollback_error is not None:
                raise RappHerdrError(
                    f"{exc}; rollback also failed: {rollback_error}"
                ) from exc
            raise

    @staticmethod
    def _health(url: str, launch_nonce: str) -> bool:
        healthy, _details = NeighborhoodManager._health_details(
            url,
            launch_nonce,
        )
        return healthy

    @staticmethod
    def _health_details(
        url: str,
        launch_nonce: str,
    ) -> tuple[bool, dict[str, Any] | None]:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=2) as response:
                healthy = (
                    200 <= int(response.status) < 300
                    and response.headers.get(LAUNCH_HEADER) == launch_nonce
                )
                if not healthy:
                    return False, None
                payload = response.read(64 * 1024 + 1)
                if len(payload) > 64 * 1024:
                    return True, None
                try:
                    value = json.loads(payload)
                except (UnicodeError, json.JSONDecodeError):
                    return True, None
                return True, value if isinstance(value, dict) else None
        except (OSError, urllib.error.URLError):
            return False, None

    def _status_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        herdr = receipt.get("herdr")
        members = receipt.get("members")
        if not isinstance(herdr, dict) or not isinstance(members, list):
            raise RappHerdrError("receipt is missing Herdr or member records")
        workspace_id = herdr.get("workspace_id")
        if not isinstance(workspace_id, str):
            raise RappHerdrError("receipt is missing workspace_id")
        workspaces = {
            value.get("workspace_id"): value for value in self.client.workspaces()
        }
        workspace = workspaces.get(workspace_id)
        if workspace is None:
            return {
                "schema": RECEIPT_SCHEMA,
                "state": "stale",
                "managed": False,
                "workspace_id": workspace_id,
                "members": [],
            }
        expected_label = herdr.get("workspace_label")
        if workspace.get("label") != expected_label:
            return {
                "schema": RECEIPT_SCHEMA,
                "state": "diverged",
                "managed": False,
                "workspace_id": workspace_id,
                "reason": "workspace label no longer matches the receipt",
                "members": [],
            }
        panes = {value.get("pane_id"): value for value in self.client.panes(workspace_id)}
        expected_pane_ids = {
            member.get("pane_id")
            for member in members
            if isinstance(member, dict)
        }
        pane_set_matches = set(panes) == expected_pane_ids
        member_status: list[dict[str, Any]] = []
        managed = pane_set_matches
        for member in members:
            if not isinstance(member, dict):
                managed = False
                continue
            pane = panes.get(member.get("pane_id"))
            workspace_path = member.get("workspace")
            matches_owner = bool(
                pane
                and pane.get("cwd") == workspace_path
                and pane.get("terminal_id") == member.get("terminal_id")
            )
            live = bool(pane and pane.get("agent") == "rapp-twin")
            managed = managed and matches_owner
            status = pane.get("agent_status") if pane else "missing"
            url = member.get("url")
            launch_nonce = member.get("launch_nonce")
            healthy = False
            health_details = None
            if isinstance(url, str) and isinstance(launch_nonce, str):
                healthy = self._health(url, launch_nonce)
                if (
                    healthy
                    and isinstance(member.get("rappid"), str)
                    and str(member["rappid"]).startswith(
                        "rappid:@rapp/persistence-probe-"
                    )
                ):
                    details_healthy, health_details = self._health_details(
                        url,
                        launch_nonce,
                    )
                    if not details_healthy:
                        health_details = None
            member_status.append(
                {
                    "name": member.get("name"),
                    "rappid": member.get("rappid"),
                    "pane_id": member.get("pane_id"),
                    "port": member.get("port"),
                    "url": url,
                    "agent_status": status,
                    "healthy": healthy,
                    "probe_target_healthy": (
                        health_details.get("target_healthy")
                        if isinstance(health_details, dict)
                        and health_details.get("service")
                        == "rapp-herdr-persistence-probe"
                        else None
                    ),
                    "probe_target_ready": (
                        health_details.get("target_ready")
                        if isinstance(health_details, dict)
                        and health_details.get("service")
                        == "rapp-herdr-persistence-probe"
                        else None
                    ),
                    "probe_relay_target": (
                        health_details.get("probe", {}).get("relay_target")
                        if isinstance(health_details, dict)
                        and health_details.get("service")
                        == "rapp-herdr-persistence-probe"
                        and isinstance(health_details.get("probe"), dict)
                        else None
                    ),
                    "probe_target_revision": (
                        health_details.get("probe", {}).get("target_revision")
                        if isinstance(health_details, dict)
                        and health_details.get("service")
                        == "rapp-herdr-persistence-probe"
                        and isinstance(health_details.get("probe"), dict)
                        else None
                    ),
                    "managed": matches_owner,
                    "live": live,
                }
            )
        all_live_and_healthy = bool(member_status) and all(
            member["live"] and member["healthy"] for member in member_status
        )
        return {
            "schema": RECEIPT_SCHEMA,
            "state": (
                "running"
                if managed and all_live_and_healthy
                else "degraded"
                if managed
                else "diverged"
            ),
            "managed": managed,
            "workspace_id": workspace_id,
            "workspace_label": expected_label,
            "reason": (
                None
                if pane_set_matches
                else "workspace pane set differs from the receipt"
            ),
            "members": member_status,
        }

    def status(
        self,
        neighborhood: Neighborhood,
    ) -> dict[str, Any]:
        context = self.client.context()
        receipt_path = self._receipt_path(neighborhood, context)
        receipt = self.receipts.load(receipt_path)
        if receipt is None:
            return {
                "schema": RECEIPT_SCHEMA,
                "state": "down",
                "managed": False,
                "members": [],
            }
        return self._status_receipt(receipt)

    def down(self, neighborhood: Neighborhood) -> dict[str, Any]:
        context = self.client.context()
        receipt_path = self._receipt_path(neighborhood, context)
        with self.receipts.operation_lock(receipt_path):
            return self._down_locked(receipt_path)

    def _down_locked(self, receipt_path: Path) -> dict[str, Any]:
        receipt = self.receipts.load(receipt_path)
        if receipt is None:
            return {
                "schema": RECEIPT_SCHEMA,
                "state": "down",
                "managed": False,
                "changed": False,
            }
        herdr = receipt.get("herdr")
        members = receipt.get("members")
        if not isinstance(herdr, dict) or not isinstance(members, list):
            raise RappHerdrError("receipt is missing Herdr or member records")
        workspace_id = herdr.get("workspace_id")
        if not isinstance(workspace_id, str):
            raise RappHerdrError("receipt is missing workspace_id")
        workspaces = {
            value.get("workspace_id"): value for value in self.client.workspaces()
        }
        workspace = workspaces.get(workspace_id)
        if workspace is None:
            self.receipts.delete(receipt_path)
            return {
                "schema": RECEIPT_SCHEMA,
                "state": "down",
                "managed": False,
                "changed": True,
                "reason": "removed stale receipt",
            }
        if workspace.get("label") != herdr.get("workspace_label"):
            raise RappHerdrError(
                "refusing to close a Herdr workspace whose label differs from the receipt"
            )
        pane_values = self.client.panes(workspace_id)
        actual_panes = {value.get("pane_id") for value in pane_values}
        expected_panes = {
            value.get("pane_id") for value in members if isinstance(value, dict)
        }
        if actual_panes != expected_panes:
            raise RappHerdrError(
                "refusing to close a Herdr workspace whose pane set differs from the receipt"
            )
        expected_workspaces = {
            value.get("pane_id"): value.get("workspace")
            for value in members
            if isinstance(value, dict)
        }
        if any(
            pane.get("cwd") != expected_workspaces.get(pane.get("pane_id"))
            for pane in pane_values
        ):
            raise RappHerdrError(
                "refusing to close a Herdr workspace whose Twin cwd differs "
                "from the receipt"
            )
        self.client.close_workspace(workspace_id)
        self.receipts.delete(receipt_path)
        return {
            "schema": RECEIPT_SCHEMA,
            "state": "down",
            "managed": False,
            "changed": True,
            "workspace_id": workspace_id,
        }
