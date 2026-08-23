from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .model import RappHerdrError

AUDIT_SCHEMA = "rapp-herdr-audit/1.0"
_MANIFEST_NAMES = {
    "rappid.json",
    "estate.json",
    "neighborhood.json",
    "members.json",
    "manifest.json",
    "catalog.json",
    "profile.json",
    "provenance.json",
    "HATCH_RECEIPT.json",
}
_SECRET_PARTS = {
    ".env",
    "token",
    "secret",
    "credential",
    "private-key",
    "private_key",
    "keys",
}
_AI_NAME = re.compile(
    r"(rapp|twin|brainstem|copilot|openrappter|openclaw|herdr|ollama|"
    r"whisper|sentinel|rbox|swarm|factory)",
    re.IGNORECASE,
)
_RAPP_LINEAGE_NAME = re.compile(r"(rapp|openrappter|rappter)", re.IGNORECASE)
_MAX_VISITED_PATHS = 20_000
_MAX_ASSETS = 5_000
_NORMALIZED_SECRET_PARTS = {
    "env",
    "key",
    "keys",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwords",
    "token",
    "tokens",
    "apikey",
    "apikeys",
    "privatekey",
    "privatekeys",
}


def _is_secret_path(path: Path) -> bool:
    for part in path.parts:
        normalized = re.sub(r"[^a-z0-9]", "", part.casefold())
        if normalized in _NORMALIZED_SECRET_PARTS or any(
            marker in normalized
            for marker in (
                "secret",
                "credential",
                "password",
                "token",
                "apikey",
                "privatekey",
            )
        ):
            return True
    return False


def _safe_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if _is_secret_path(path):
        return None, "secret-bearing path skipped"
    try:
        if path.stat().st_size > 2_000_000:
            return None, "manifest exceeds 2 MB limit"
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, str(exc)
    if not isinstance(value, dict):
        return None, "manifest is not an object"
    return value, None


def _classification(path: Path, value: dict[str, Any]) -> str:
    schema = value.get("schema")
    if isinstance(schema, str):
        lowered = schema.casefold()
        if lowered == "rapp/1" or lowered.startswith("rapp/1-"):
            return "declared-rapp1-unverified"
        if lowered.startswith("rapp"):
            return "legacy-rapp"
    if value.get("rappid") is not None or ".rapp" in path.parts or ".brainstem" in path.parts:
        return "legacy-rapp"
    return "non-rapp-ai"


def _asset_type(path: Path, value: dict[str, Any]) -> str:
    if path.name == "estate.json":
        return "estate"
    if path.name == "neighborhood.json":
        return "neighborhood"
    if path.name == "members.json":
        return "membership"
    if path.name == "HATCH_RECEIPT.json":
        return "hatch-receipt"
    if path.name == "manifest.json":
        return str(value.get("layer") or value.get("kind") or "manifest")
    kind = value.get("kind")
    return str(kind) if isinstance(kind, str) and kind else "organism"


def _manifest_asset(
    path: Path,
    *,
    assigned_rappids: set[str],
) -> dict[str, Any]:
    value, error = _safe_json(path)
    if value is None:
        return {
            "path": str(path),
            "type": "invalid-manifest",
            "compliance": "malformed",
            "error": error,
            "active": False,
            "runnable": False,
        }
    rappid = value.get("rappid") or value.get("neighborhood_rappid")
    parent = path.parent
    entrypoints = [
        name
        for name in ("brainstem.py", "serve.py", "agent.py", "run", "start.sh", "start.ps1")
        if (parent / name).exists()
    ]
    return {
        "path": str(path),
        "workspace": str(parent),
        "type": _asset_type(path, value),
        "name": (
            value.get("display_name")
            or value.get("name")
            or value.get("id")
            or parent.name
        ),
        "rappid": rappid,
        "schema": value.get("schema"),
        "kind": value.get("kind"),
        "compliance": _classification(path, value),
        "assigned": isinstance(rappid, str) and rappid in assigned_rappids,
        "runnable": bool(entrypoints),
        "entrypoints": entrypoints,
        "active": False,
    }


def _walk_manifests(
    root: Path,
    budget: dict[str, Any],
    max_depth: int = 6,
) -> Iterable[Path]:
    return _bounded_files(
        root,
        max_depth=max_depth,
        budget=budget,
        predicate=lambda path: (
            path.suffix.casefold() == ".json"
            and path.name in _MANIFEST_NAMES
        ),
    )


def _bounded_files(
    root: Path,
    *,
    max_depth: int,
    budget: dict[str, Any],
    predicate,
) -> tuple[Path, ...]:
    if (
        budget.get("truncated")
        or not root.is_dir()
        or root.is_symlink()
        or _is_secret_path(root)
    ):
        return ()
    resolved_root = root.resolve()
    values = []
    for current, directories, files in os.walk(resolved_root, followlinks=False):
        current_path = Path(current)
        try:
            relative = current_path.relative_to(resolved_root)
        except ValueError:
            directories[:] = []
            continue
        depth = len(relative.parts)
        budget["visited"] += 1
        if budget["visited"] > _MAX_VISITED_PATHS:
            budget["truncated"] = True
            directories[:] = []
            break
        directories[:] = [
            name
            for name in directories
            if depth < max_depth
            and not (current_path / name).is_symlink()
            and not _is_secret_path(current_path / name)
        ]
        for name in files:
            budget["visited"] += 1
            if budget["visited"] > _MAX_VISITED_PATHS:
                budget["truncated"] = True
                directories[:] = []
                break
            path = current_path / name
            if path.is_symlink() or _is_secret_path(path):
                continue
            resolved = path.resolve()
            if resolved != resolved_root and resolved_root not in resolved.parents:
                continue
            if predicate(resolved):
                values.append(resolved)
                if len(values) + budget["assets"] >= _MAX_ASSETS:
                    budget["truncated"] = True
                    directories[:] = []
                    break
        if budget["truncated"]:
            break
    budget["assets"] += len(values)
    return tuple(values)


def _administrative_twin_entries(
    root: Path,
    budget: dict[str, Any],
) -> list[dict[str, Any]]:
    values = []
    if not root.is_dir():
        return values
    for entry in os.scandir(root):
        budget["visited"] += 1
        if (
            budget["visited"] > _MAX_VISITED_PATHS
            or budget["assets"] >= _MAX_ASSETS
        ):
            budget["truncated"] = True
            break
        child = Path(entry.path)
        if (
            not child.is_dir()
            or child.is_symlink()
            or not child.name.startswith(".")
            or _is_secret_path(child)
        ):
            continue
        values.append(
            {
                "path": str(child),
                "name": child.name,
                "type": "administrative-metadata",
                "compliance": "not-an-organism",
                "active": False,
                "runnable": False,
            }
        )
        budget["assets"] += 1
    return values


def _git_workspaces(
    roots: Iterable[Path],
    budget: dict[str, Any],
) -> list[dict[str, Any]]:
    values = []
    seen: set[Path] = set()
    for root in roots:
        if budget["truncated"]:
            break
        if not root.is_dir() or root.is_symlink() or _is_secret_path(root):
            continue
        if (root / ".git").exists():
            candidates = (root,)
        else:
            candidates = (
                Path(entry.path)
                for entry in os.scandir(root)
                if entry.is_dir(follow_symlinks=False)
            )
        for candidate in candidates:
            budget["visited"] += 1
            if (
                budget["visited"] > _MAX_VISITED_PATHS
                or budget["assets"] >= _MAX_ASSETS
            ):
                budget["truncated"] = True
                break
            workspace = candidate.resolve()
            resolved_root = root.resolve()
            if (
                workspace in seen
                or _is_secret_path(workspace)
                or not (workspace / ".git").exists()
                or (
                    workspace != resolved_root
                    and resolved_root not in workspace.parents
                )
            ):
                continue
            seen.add(workspace)
            if (workspace / "RAPP1_AUTHORITY.json").is_file() or (
                workspace / "SPEC-rapp1.md"
            ).is_file():
                compliance = "rapp1-aware-unverified"
            elif _RAPP_LINEAGE_NAME.search(workspace.name) or (
                workspace / "rappid.json"
            ).is_file():
                compliance = "legacy-rapp"
            else:
                compliance = "non-rapp-ai"
            entrypoints = [
                name
                for name in (
                    "brainstem.py",
                    "package.json",
                    "pyproject.toml",
                    "Cargo.toml",
                    "agent.py",
                )
                if (workspace / name).is_file()
            ]
            values.append(
                {
                    "path": str(workspace),
                    "workspace": str(workspace),
                    "name": workspace.name,
                    "type": "git-workspace",
                    "compliance": compliance,
                    "active": False,
                    "runnable": bool(entrypoints),
                    "entrypoints": entrypoints,
                }
            )
            budget["assets"] += 1
    return values


def _egg_assets(
    roots: Iterable[Path],
    budget: dict[str, Any],
) -> list[dict[str, Any]]:
    values = []
    for root in roots:
        for path in _bounded_files(
            root,
            max_depth=5,
            budget=budget,
            predicate=lambda candidate: candidate.suffix.casefold() == ".egg",
        ):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            values.append(
                {
                    "path": str(path.resolve()),
                    "workspace": str(path.parent.resolve()),
                    "name": path.name,
                    "type": "egg",
                    "compliance": "package-unverified",
                    "active": False,
                    "runnable": False,
                    "bytes": size,
                }
            )
            if len(values) >= _MAX_ASSETS:
                return values
    return values


def _workspace_registry(
    home: Path,
    allowed_roots: Iterable[Path],
    budget: dict[str, Any],
) -> list[dict[str, Any]]:
    path = home / ".rapp" / "workspace-registry.json"
    value, _error = _safe_json(path)
    if value is None:
        return []
    workspaces = value.get("workspaces")
    if not isinstance(workspaces, list):
        return []
    results = []
    resolved_roots = [
        root.expanduser().resolve()
        for root in allowed_roots
        if root.expanduser().exists() and not _is_secret_path(root.expanduser())
    ]
    for workspace in workspaces:
        budget["visited"] += 1
        if (
            budget["visited"] > _MAX_VISITED_PATHS
            or budget["assets"] >= _MAX_ASSETS
        ):
            budget["truncated"] = True
            break
        if not isinstance(workspace, dict):
            continue
        raw_path = workspace.get("path")
        resolved = (
            Path(raw_path).expanduser().resolve()
            if isinstance(raw_path, str) and raw_path
            else None
        )
        if (
            not isinstance(raw_path, str)
            or _is_secret_path(Path(raw_path))
            or resolved is None
            or _is_secret_path(resolved)
            or not any(
                resolved == root or root in resolved.parents
                for root in resolved_roots
            )
        ):
            continue
        results.append(
            {
                "path": str(resolved) if resolved else raw_path,
                "name": workspace.get("name"),
                "rappid": workspace.get("rappid"),
                "type": "workspace-pointer",
                "compliance": "declared-rapp1-unverified",
                "active": bool(workspace.get("active")),
                "exists": bool(resolved and resolved.exists()),
                "world_id": workspace.get("world_id"),
                "runnable": False,
            }
        )
        budget["assets"] += 1
    return results


def _unix_listeners() -> list[dict[str, Any]]:
    try:
        lsof = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if lsof.returncode != 0:
        return []
    listeners = []
    seen: set[tuple[str, int | None, str, int]] = set()
    for line in lsof.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        process, pid = parts[0], parts[1]
        address = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        match = re.search(r"(.+):(\d+)(?:\s+\(LISTEN\))?$", address)
        if not match:
            continue
        host, port = match.group(1), int(match.group(2))
        numeric_pid = int(pid) if pid.isdigit() else None
        key = (process, numeric_pid, host, port)
        if key in seen:
            continue
        seen.add(key)
        listeners.append(
            {
                "process": process,
                "pid": numeric_pid,
                "address": host,
                "port": port,
                "scope": "loopback" if host in {"127.0.0.1", "[::1]", "localhost"} else "network",
                "estate_relevant": process.casefold() in {
                    "ollama", "herdr", "copilot", "claude", "openrappter"
                }
                or port in {
                    5272, 7071, 7080, 7081, 7083, 7085, 7090, 7337, 7447,
                    7790, 7793, 7794, 7795, 7799, 7861, 7862, 8765, 8888,
                    9789, 9797, 9798, 11434, 18789, 18790, 18791, 18792,
                },
            }
        )
    return listeners


def _windows_listeners() -> list[dict[str, Any]]:
    script = (
        "$items=@();"
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|ForEach-Object{"
        "$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
        "$items+=[pscustomobject]@{process=if($p){$p.ProcessName}else{'unknown'};"
        "pid=$_.OwningProcess;address=$_.LocalAddress;port=$_.LocalPort}};"
        "$items|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    rows = value if isinstance(value, list) else [value]
    listeners = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        process = str(row.get("process") or "unknown")
        address = str(row.get("address") or "")
        port = int(row.get("port") or 0)
        listeners.append(
            {
                "process": process,
                "pid": row.get("pid"),
                "address": address,
                "port": port,
                "scope": "loopback" if address in {"127.0.0.1", "::1"} else "network",
                "estate_relevant": process.casefold() in {
                    "ollama", "herdr", "copilot", "claude", "openrappter"
                }
                or port in {
                    5272, 7071, 7080, 7081, 7083, 7085, 7090, 7337,
                    7799, 7861, 7862, 8765, 9789, 9797, 11434, 18790,
                },
            }
        )
    return listeners


def _unix_jobs() -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    jobs = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) != 3 or not _AI_NAME.search(parts[2]):
            continue
        jobs.append(
            {
                "label": parts[2],
                "pid": int(parts[0]) if parts[0].isdigit() else None,
                "status": parts[1],
            }
        )
    return jobs


def _windows_jobs() -> list[dict[str, Any]]:
    script = (
        "$items=@();"
        "Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{"
        "$_.TaskName -match 'RAPP|Herdr|OpenRappter|Palworld|Twin|Agent'}|"
        "ForEach-Object{$i=Get-ScheduledTaskInfo $_ -ErrorAction SilentlyContinue;"
        "$items+=[pscustomobject]@{label=$_.TaskName;state=[string]$_.State;"
        "last_result=if($i){$i.LastTaskResult}else{$null}}};"
        "$items|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    rows = value if isinstance(value, list) else [value]
    return [row for row in rows if isinstance(row, dict)]


def _herdr_snapshot(binary: str, session: str) -> dict[str, Any]:
    def json_command(*args: str) -> dict[str, Any] | None:
        try:
            result = subprocess.run(
                [binary, *args],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    sessions = json_command("session", "list", "--json")
    workspaces = json_command("--session", session, "workspace", "list")
    agents = json_command("--session", session, "agent", "list")
    workspace_values = (
        ((workspaces or {}).get("result") or {}).get("workspaces") or []
    )
    agent_values = ((agents or {}).get("result") or {}).get("agents") or []
    return {
        "sessions": (sessions or {}).get("sessions", []),
        "workspace_count": len(workspace_values),
        "pane_count": sum(
            int(workspace.get("pane_count") or 0)
            for workspace in workspace_values
            if isinstance(workspace, dict)
        ),
        "agent_count": len(agent_values),
        "agent_kinds": sorted(
            {
                agent.get("agent")
                for agent in agent_values
                if isinstance(agent, dict) and agent.get("agent")
            }
        ),
    }


def _stale_pid_records(root: Path) -> dict[str, int]:
    total = stale = 0
    if not root.is_dir():
        return {"total": 0, "stale": 0}
    for path in root.glob("*.pid"):
        total += 1
        try:
            pid = int(path.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
        except (OSError, ValueError, OverflowError):
            stale += 1
    return {"total": total, "stale": stale}


def audit_machine(
    payload: dict[str, Any],
    *,
    assigned_rappids: set[str],
) -> dict[str, Any]:
    home = Path.home()
    roots = [
        home / ".rapp" / "twins",
        home / ".rapp" / "neighborhoods",
        home / ".rapp" / "estates",
        home / ".rapp" / "rboxes",
        home / ".rapp" / "hub",
        home / ".brainstem" / "twins",
    ]
    for raw in payload.get("audit_roots", []):
        if isinstance(raw, str) and raw:
            roots.append(Path(raw).expanduser().resolve())
    assets = []
    budget: dict[str, Any] = {
        "visited": 0,
        "assets": 0,
        "truncated": False,
    }
    seen_paths: set[str] = set()
    for root in roots:
        for path in _walk_manifests(root, budget):
            key = str(path.resolve())
            if key in seen_paths:
                continue
            seen_paths.add(key)
            assets.append(
                _manifest_asset(path.resolve(), assigned_rappids=assigned_rappids)
            )
    assets.extend(
        _administrative_twin_entries(
            home / ".rapp" / "twins",
            budget,
        )
    )
    assets.extend(_workspace_registry(home, roots, budget))
    assets.extend(_git_workspaces(roots, budget))
    assets.extend(_egg_assets(roots, budget))
    if len(assets) > _MAX_ASSETS:
        assets = assets[:_MAX_ASSETS]
        budget["truncated"] = True
    listeners = (
        _windows_listeners()
        if os.name == "nt"
        else _unix_listeners()
    )
    relevant_listeners = [
        listener for listener in listeners if listener.get("estate_relevant")
    ]
    herdr_binary = str(
        Path(str(payload.get("herdr_bin") or "herdr")).expanduser()
    )
    herdr = _herdr_snapshot(
        herdr_binary,
        str(payload.get("session") or "rapp-estate"),
    )
    compliance_counts: dict[str, int] = {}
    for asset in assets:
        compliance = str(asset.get("compliance") or "unknown")
        compliance_counts[compliance] = compliance_counts.get(compliance, 0) + 1
    findings = []
    stale_pids = _stale_pid_records(home / ".rapp" / "pids")
    if stale_pids["stale"]:
        findings.append(
            {
                "severity": "warning",
                "kind": "stale-pids",
                "message": (
                    f"{stale_pids['stale']} of {stale_pids['total']} "
                    "RAPP PID records are stale"
                ),
            }
        )
    network_listeners = [
        listener for listener in relevant_listeners
        if listener.get("scope") == "network"
    ]
    if network_listeners:
        findings.append(
            {
                "severity": "warning",
                "kind": "network-listeners",
                "message": (
                    f"{len(network_listeners)} estate-relevant listeners "
                    "are bound beyond loopback"
                ),
            }
        )
    if budget["truncated"]:
        findings.append(
            {
                "severity": "warning",
                "kind": "audit-truncated",
                "message": (
                    "Audit traversal reached its configured path or asset limit"
                ),
            }
        )
    return {
        "schema": AUDIT_SCHEMA,
        "ok": True,
        "machine": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "herdr": herdr,
        "assets": assets,
        "asset_count": len(assets),
        "compliance_counts": compliance_counts,
        "services": relevant_listeners,
        "service_count": len(relevant_listeners),
        "jobs": _windows_jobs() if os.name == "nt" else _unix_jobs(),
        "findings": findings,
        "stale_pids": stale_pids,
        "scan": budget,
    }
