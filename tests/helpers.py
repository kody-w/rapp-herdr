from __future__ import annotations

import json
from pathlib import Path


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def create_neighborhood(root: Path, count: int = 4) -> tuple[Path, list[str]]:
    rappids = [f"rappid:@test/twin-{index}:{index:064x}" for index in range(1, count + 1)]
    manifest = root / "neighborhood.json"
    write_json(
        manifest,
        {
            "schema": "rapp-neighborhood/1.0",
            "name": "four-twin-lab",
            "display_name": "Four Twin Lab",
            "neighborhood_rappid": "rappid:@test/lab:" + "a" * 64,
            "members_path": "members.json",
        },
    )
    write_json(
        root / "members.json",
        {
            "schema": "rapp-neighborhood-members/1.0",
            "neighborhood_rappid": "rappid:@test/lab:" + "a" * 64,
            "members": [
                {"rappid": rappid, "role": "neighbor"} for rappid in rappids
            ],
        },
    )
    return manifest, rappids


def create_twin(root: Path, name: str, rappid: str) -> Path:
    workspace = root / name
    workspace.mkdir(parents=True)
    write_json(
        workspace / "rappid.json",
        {
            "schema": "rapp/1",
            "rappid": rappid,
            "kind": "twin",
            "name": name,
            "display_name": name.replace("-", " ").title(),
        },
    )
    (workspace / "brainstem.py").write_text("# test brainstem\n", encoding="utf-8")
    (workspace / "soul.md").write_text(f"# {name}\n", encoding="utf-8")
    (workspace / "agents").mkdir()
    (workspace / "agents" / "basic_agent.py").write_text("# basic\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text(
        "Flask>=3\nrequests>=2\npython-dotenv>=1\n",
        encoding="utf-8",
    )
    return workspace
