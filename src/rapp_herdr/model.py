from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MAX_MANIFEST_BYTES = 1_000_000
SUPPORTED_NEIGHBORHOOD_SCHEMAS = {
    "rapp-neighborhood/1.0",
    "rapp-vneighborhood/1.0",
}
MEMBERS_SCHEMA = "rapp-neighborhood-members/1.0"


class RappHerdrError(RuntimeError):
    """A user-facing integration failure."""


@dataclass(frozen=True)
class Neighborhood:
    schema: str
    name: str
    semantic_id: str
    local_key: str
    manifest_path: Path
    members_path: Path
    member_rappids: tuple[str, ...]


@dataclass(frozen=True)
class TwinWorkspace:
    name: str
    rappid: str
    workspace: Path
    requirements: Path | None


@dataclass(frozen=True)
class NeighborhoodTopology:
    neighborhood: Neighborhood
    twins: tuple[TwinWorkspace, ...]
    unresolved_rappids: tuple[str, ...]


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RappHerdrError(f"{label} is not readable: {path}: {exc}") from exc
    if size > MAX_MANIFEST_BYTES:
        raise RappHerdrError(
            f"{label} exceeds the {MAX_MANIFEST_BYTES}-byte safety limit: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"{label} is not valid UTF-8 JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"{label} must contain a JSON object: {path}")
    return value


def _required_text(value: Any, field: str, path: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RappHerdrError(f"{path}: {field} must be a non-empty string")
    return value.strip()


def _members_path(manifest: dict[str, Any], manifest_path: Path) -> Path:
    raw = manifest.get("members_path", "members.json")
    relative = Path(_required_text(raw, "members_path", manifest_path))
    if relative.is_absolute():
        raise RappHerdrError(
            f"{manifest_path}: members_path must stay inside the neighborhood directory"
        )
    parent = manifest_path.parent.resolve()
    resolved = (parent / relative).resolve()
    if resolved != parent and parent not in resolved.parents:
        raise RappHerdrError(
            f"{manifest_path}: members_path escapes the neighborhood directory"
        )
    return resolved


def load_neighborhood(
    manifest_path: str | Path,
    members_path: str | Path | None = None,
) -> Neighborhood:
    manifest_file = Path(manifest_path).expanduser().resolve()
    manifest = _load_json(manifest_file, "neighborhood manifest")
    schema = _required_text(manifest.get("schema"), "schema", manifest_file)
    if schema not in SUPPORTED_NEIGHBORHOOD_SCHEMAS:
        supported = ", ".join(sorted(SUPPORTED_NEIGHBORHOOD_SCHEMAS))
        raise RappHerdrError(
            f"{manifest_file}: unsupported neighborhood schema {schema!r}; "
            f"supported: {supported}"
        )

    if schema == "rapp-neighborhood/1.0":
        semantic_id = _required_text(
            manifest.get("neighborhood_rappid"),
            "neighborhood_rappid",
            manifest_file,
        )
        name = _required_text(
            manifest.get("display_name") or manifest.get("name"),
            "display_name or name",
            manifest_file,
        )
    else:
        channel = _required_text(manifest.get("channel"), "channel", manifest_file)
        name = _required_text(manifest.get("name"), "name", manifest_file)
        semantic_id = f"channel:{channel}"

    if members_path is None:
        roster_file = _members_path(manifest, manifest_file)
    else:
        roster_file = Path(members_path).expanduser().resolve()
    roster = _load_json(roster_file, "neighborhood members")
    roster_schema = _required_text(roster.get("schema"), "schema", roster_file)
    if roster_schema != MEMBERS_SCHEMA:
        raise RappHerdrError(
            f"{roster_file}: expected schema {MEMBERS_SCHEMA!r}, got {roster_schema!r}"
        )
    if schema == "rapp-neighborhood/1.0":
        roster_id = roster.get("neighborhood_rappid")
        if isinstance(roster_id, str) and roster_id and roster_id != semantic_id:
            raise RappHerdrError(
                f"{roster_file}: neighborhood_rappid does not match {manifest_file}"
            )

    members = roster.get("members")
    if not isinstance(members, list):
        raise RappHerdrError(f"{roster_file}: members must be an array")
    rappids: list[str] = []
    seen: set[str] = set()
    for index, member in enumerate(members):
        if not isinstance(member, dict):
            raise RappHerdrError(f"{roster_file}: members[{index}] must be an object")
        rappid = _required_text(member.get("rappid"), f"members[{index}].rappid", roster_file)
        if rappid in seen:
            raise RappHerdrError(f"{roster_file}: duplicate member rappid {rappid!r}")
        seen.add(rappid)
        rappids.append(rappid)
    if not rappids:
        raise RappHerdrError(f"{roster_file}: members must include at least one rappid")

    key_material = f"{manifest_file}\0{schema}\0{semantic_id}".encode()
    local_key = hashlib.sha256(key_material).hexdigest()
    return Neighborhood(
        schema=schema,
        name=name,
        semantic_id=semantic_id,
        local_key=local_key,
        manifest_path=manifest_file,
        members_path=roster_file,
        member_rappids=tuple(rappids),
    )


def _candidate_workspaces(roots: Iterable[str | Path]) -> tuple[Path, ...]:
    candidates: set[Path] = set()
    for raw_root in roots:
        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            raise RappHerdrError(f"estate root is not a directory: {root}")
        if (root / "rappid.json").is_file():
            candidates.add(root)
            continue
        try:
            children = sorted(root.iterdir())
        except OSError as exc:
            raise RappHerdrError(f"cannot enumerate estate root {root}: {exc}") from exc
        for child in children:
            if child.is_dir() and (child / "rappid.json").is_file():
                resolved = child.resolve()
                if resolved != root and root not in resolved.parents:
                    raise RappHerdrError(
                        f"Twin workspace symlink escapes estate root {root}: {child}"
                    )
                candidates.add(resolved)
    return tuple(sorted(candidates))


def resolve_topology(
    neighborhood: Neighborhood,
    estate_roots: Iterable[str | Path],
    *,
    require_all_local: bool = False,
) -> NeighborhoodTopology:
    by_rappid: dict[str, TwinWorkspace] = {}
    by_workspace: dict[Path, str] = {}
    selected_rappids = set(neighborhood.member_rappids)
    for workspace in _candidate_workspaces(estate_roots):
        identity_file = workspace / "rappid.json"
        identity = _load_json(identity_file, "Twin identity")
        raw_rappid = identity.get("rappid")
        if not isinstance(raw_rappid, str) or not raw_rappid.strip():
            continue
        rappid = raw_rappid.strip()
        if rappid not in selected_rappids:
            continue
        kind = _required_text(identity.get("kind"), "kind", identity_file).casefold()
        if kind != "twin":
            continue
        if not (workspace / "brainstem.py").is_file():
            raise RappHerdrError(f"Twin workspace is missing brainstem.py: {workspace}")
        if not (workspace / "soul.md").is_file():
            raise RappHerdrError(f"Twin workspace is missing soul.md: {workspace}")
        if not (workspace / "agents").is_dir():
            raise RappHerdrError(f"Twin workspace is missing agents/: {workspace}")
        if rappid in by_rappid:
            raise RappHerdrError(
                f"duplicate local Twin identity {rappid!r}: "
                f"{by_rappid[rappid].workspace} and {workspace}"
            )
        if workspace in by_workspace:
            raise RappHerdrError(
                f"canonical Twin workspace is enrolled twice: {workspace}"
            )
        name = _required_text(
            identity.get("display_name") or identity.get("name"),
            "display_name or name",
            identity_file,
        )
        requirements = workspace / "requirements.txt"
        if not requirements.is_file():
            requirements = workspace / "installer" / "requirements.txt"
        twin = TwinWorkspace(
            name=name,
            rappid=rappid,
            workspace=workspace,
            requirements=requirements if requirements.is_file() else None,
        )
        by_rappid[rappid] = twin
        by_workspace[workspace] = rappid

    twins = tuple(
        by_rappid[rappid]
        for rappid in neighborhood.member_rappids
        if rappid in by_rappid
    )
    unresolved = tuple(
        rappid for rappid in neighborhood.member_rappids if rappid not in by_rappid
    )
    if require_all_local and unresolved:
        raise RappHerdrError(
            "neighborhood members are not present in the selected estate roots: "
            + ", ".join(unresolved)
        )
    if not twins:
        raise RappHerdrError(
            "none of the neighborhood's Twin identities resolve in the selected estate roots"
        )
    return NeighborhoodTopology(
        neighborhood=neighborhood,
        twins=twins,
        unresolved_rappids=unresolved,
    )
