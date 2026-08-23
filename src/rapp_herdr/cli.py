from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from .herdr import HerdrClient
from .manager import NeighborhoodManager
from .model import RappHerdrError, load_neighborhood, resolve_topology
from .receipts import ReceiptStore
from .supervisor import supervise


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("manifest", help="Path to neighborhood.json")
    parser.add_argument("--members", help="Override the members.json path")
    parser.add_argument("--session", help="Target a named Herdr session")
    parser.add_argument("--herdr", help="Path to the Herdr binary")
    parser.add_argument("--receipt-root", help="Override ~/.config/rapp-herdr")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapp-herdr",
        description="Manage RAPP Twin neighborhoods in Herdr.",
    )
    parser.add_argument("--version", action="version", version="rapp-herdr 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    neighborhood = commands.add_parser("neighborhood")
    neighborhood_commands = neighborhood.add_subparsers(
        dest="neighborhood_command", required=True
    )

    up = neighborhood_commands.add_parser("up")
    _add_common(up)
    up.add_argument(
        "--estate-root",
        action="append",
        default=[],
        help="Root containing local Twin workspaces; repeatable",
    )
    up.add_argument("--base-port", type=int, default=7081)
    up.add_argument("--require-all-local", action="store_true")
    up.add_argument("--brainstem-python")
    up.add_argument("--no-bootstrap", action="store_true")
    up.add_argument("--listen-host", default="127.0.0.1")
    up.add_argument("--entrypoint", default="brainstem.py")

    status = neighborhood_commands.add_parser("status")
    _add_common(status)

    down = neighborhood_commands.add_parser("down")
    _add_common(down)

    doctor = commands.add_parser("doctor")
    doctor.add_argument("--session")
    doctor.add_argument("--herdr")

    twin = commands.add_parser("_twin", help=argparse.SUPPRESS)
    twin.add_argument("--workspace", required=True)
    twin.add_argument("--python", required=True)
    twin.add_argument("--port", type=int, required=True)
    twin.add_argument("--name", required=True)
    twin.add_argument("--rappid", required=True)
    twin.add_argument("--neighborhood", required=True)
    twin.add_argument("--listen-host", required=True)
    twin.add_argument("--entrypoint", required=True)
    twin.add_argument("--launch-nonce", required=True)
    twin.add_argument("--herdr", required=True)
    return parser


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _manager(args) -> NeighborhoodManager:
    return NeighborhoodManager(
        HerdrClient(binary=args.herdr, session=args.session),
        ReceiptStore(args.receipt_root),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "_twin":
            return supervise(
                workspace=Path(args.workspace).expanduser().resolve(),
                python=Path(args.python).expanduser().resolve(),
                port=args.port,
                name=args.name,
                rappid=args.rappid,
                neighborhood=args.neighborhood,
                listen_host=args.listen_host,
                entrypoint=args.entrypoint,
                launch_nonce=args.launch_nonce,
                herdr_binary=args.herdr,
            )
        if args.command == "doctor":
            client = HerdrClient(binary=args.herdr, session=args.session)
            context = client.context()
            _print(
                {
                    "ok": True,
                    "herdr_version": ".".join(str(part) for part in context.version),
                    "herdr_socket": context.socket_path,
                    "inside_herdr": os.environ.get("HERDR_ENV") == "1",
                    "default_estate_root": str(Path.home() / ".rapp" / "twins"),
                }
            )
            return 0

        neighborhood = load_neighborhood(args.manifest, args.members)
        manager = _manager(args)
        if args.neighborhood_command == "up":
            estate_roots = args.estate_root or [Path.home() / ".rapp" / "twins"]
            topology = resolve_topology(
                neighborhood,
                estate_roots,
                require_all_local=args.require_all_local,
            )
            result = manager.up(
                topology,
                base_port=args.base_port,
                brainstem_python=args.brainstem_python,
                bootstrap=not args.no_bootstrap,
                listen_host=args.listen_host,
                entrypoint=args.entrypoint,
            )
        elif args.neighborhood_command == "status":
            result = manager.status(neighborhood)
        else:
            result = manager.down(neighborhood)
        _print(result)
        return 0
    except RappHerdrError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "error": "interrupted"}), file=sys.stderr)
        return 130
