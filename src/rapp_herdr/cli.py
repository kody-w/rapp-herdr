from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from .buddy import decode_buddy_payload, run_buddy_device
from .cell import decode_cell_payload, load_cell_payload, run_cell
from .estate import (
    EstateManager,
    decode_device_payload,
    load_estate,
    run_estate_device,
)
from .herdr import HerdrClient
from .manager import NeighborhoodManager
from .model import RappHerdrError, load_neighborhood, resolve_topology
from .probe import decode_probe_payload, run_probe_device
from .receipts import ReceiptStore
from .supervisor import supervise
from .ui import run_ui


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

    estate = commands.add_parser("estate")
    estate_commands = estate.add_subparsers(
        dest="estate_command",
        required=True,
    )
    for action in ("plan", "up", "status", "audit", "down"):
        action_parser = estate_commands.add_parser(action)
        action_parser.add_argument("manifest", help="Path to rapp-herdr estate JSON")
        action_parser.add_argument("--ssh", help="Path to the SSH binary")
    estate_probe = estate_commands.add_parser("probe")
    estate_probe.add_argument(
        "probe_action",
        choices=["seed", "start", "stop", "restart", "mark", "verify"],
    )
    estate_probe.add_argument("manifest", help="Path to rapp-herdr estate JSON")
    estate_probe.add_argument("--base-port", type=int, default=7199)
    estate_probe.add_argument("--ssh", help="Path to the SSH binary")
    estate_buddy = estate_commands.add_parser("buddy")
    estate_buddy_commands = estate_buddy.add_subparsers(
        dest="buddy_action",
        required=True,
    )
    estate_buddy_create = estate_buddy_commands.add_parser("create")
    estate_buddy_create.add_argument(
        "manifest",
        help="Path to rapp-herdr estate JSON",
    )
    estate_buddy_create.add_argument("--device")
    estate_buddy_create.add_argument("--name")
    estate_buddy_create.add_argument("--role")
    estate_buddy_create.add_argument(
        "--ui",
        choices=["auto", "chat", "rapplication"],
        default="auto",
    )
    estate_buddy_create.add_argument("--port-start", type=int, default=7200)
    estate_buddy_create.add_argument(
        "--stdin",
        action="store_true",
        help="Read buddy definition JSON from stdin",
    )
    estate_buddy_create.add_argument("--ssh", help="Path to the SSH binary")
    estate_buddy_list = estate_buddy_commands.add_parser("list")
    estate_buddy_list.add_argument(
        "manifest",
        help="Path to rapp-herdr estate JSON",
    )
    estate_buddy_list.add_argument("--ssh", help="Path to the SSH binary")
    estate_buddy_chat = estate_buddy_commands.add_parser("chat")
    estate_buddy_chat.add_argument(
        "manifest",
        help="Path to rapp-herdr estate JSON",
    )
    estate_buddy_chat.add_argument("--buddy")
    estate_buddy_chat.add_argument("--message")
    estate_buddy_chat.add_argument("--session-id")
    estate_buddy_chat.add_argument(
        "--stdin",
        action="store_true",
        help="Read buddy chat JSON from stdin",
    )
    estate_buddy_chat.add_argument("--ssh", help="Path to the SSH binary")

    doctor = commands.add_parser("doctor")
    doctor.add_argument("--session")
    doctor.add_argument("--herdr")

    ui = commands.add_parser("ui")
    ui.add_argument("manifest", help="Path to rapp-herdr estate JSON")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--open", action="store_true")

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

    estate_device = commands.add_parser("_estate-device", help=argparse.SUPPRESS)
    estate_device.add_argument("action", choices=["up", "status", "audit", "down"])
    estate_device.add_argument("--payload", required=True)

    probe_device = commands.add_parser("_probe-device", help=argparse.SUPPRESS)
    probe_device.add_argument("action", choices=["seed", "mark", "verify"])
    probe_device.add_argument("--payload", required=True)

    buddy_device = commands.add_parser("_buddy-device", help=argparse.SUPPRESS)
    buddy_device.add_argument(
        "action",
        choices=["create", "handshake", "delete", "chat"],
    )
    buddy_device_payload = buddy_device.add_mutually_exclusive_group(
        required=True
    )
    buddy_device_payload.add_argument("--payload")
    buddy_device_payload.add_argument(
        "--payload-stdin",
        action="store_true",
    )

    cell = commands.add_parser("_cell", help=argparse.SUPPRESS)
    cell_payload = cell.add_mutually_exclusive_group(required=True)
    cell_payload.add_argument("--payload")
    cell_payload.add_argument("--payload-file")
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
                python=Path(args.python).expanduser().absolute(),
                port=args.port,
                name=args.name,
                rappid=args.rappid,
                neighborhood=args.neighborhood,
                listen_host=args.listen_host,
                entrypoint=args.entrypoint,
                launch_nonce=args.launch_nonce,
                herdr_binary=args.herdr,
            )
        if args.command == "_estate-device":
            result = run_estate_device(
                args.action,
                decode_device_payload(args.payload),
            )
            _print(result)
            return 0 if result.get("ok") else 1
        if args.command == "_probe-device":
            result = run_probe_device(
                args.action,
                decode_probe_payload(args.payload),
            )
            _print(result)
            return 0 if result.get("ok") else 1
        if args.command == "_buddy-device":
            encoded = args.payload
            if args.payload_stdin:
                encoded = sys.stdin.read(2 * 1024 * 1024 + 1)
                if len(encoded) > 2 * 1024 * 1024:
                    raise RappHerdrError(
                        "buddy stdin payload exceeds 2 MiB"
                    )
            result = run_buddy_device(
                args.action,
                decode_buddy_payload(encoded),
            )
            _print(result)
            return 0 if result.get("ok") else 1
        if args.command == "_cell":
            payload = (
                decode_cell_payload(args.payload)
                if args.payload
                else load_cell_payload(args.payload_file)
            )
            return run_cell(payload)
        if args.command == "estate":
            estate = load_estate(args.manifest)
            manager = EstateManager(estate, ssh_binary=args.ssh)
            if args.estate_command == "probe":
                result = manager.probe(
                    args.probe_action,
                    base_port=args.base_port,
                )
            elif args.estate_command == "buddy":
                buddy_input: dict[str, object] = {}
                if getattr(args, "stdin", False):
                    try:
                        loaded = json.load(sys.stdin)
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise RappHerdrError(
                            f"invalid buddy stdin JSON: {exc}"
                        ) from exc
                    if not isinstance(loaded, dict):
                        raise RappHerdrError(
                            "buddy stdin JSON must contain an object"
                        )
                    buddy_input = loaded
                if args.buddy_action == "create":
                    def required_buddy_text(
                        key: str,
                        fallback: object,
                    ) -> str:
                        value = (
                            buddy_input[key]
                            if key in buddy_input
                            else fallback
                        )
                        if not isinstance(value, str) or not value.strip():
                            raise RappHerdrError(
                                f"buddy {key} must be a non-empty string"
                            )
                        return value

                    raw_ui = (
                        buddy_input["ui"]
                        if "ui" in buddy_input
                        else args.ui
                    )
                    if (
                        not isinstance(raw_ui, str)
                        or raw_ui not in {"auto", "chat", "rapplication"}
                    ):
                        raise RappHerdrError(
                            "buddy ui must be auto, chat, or rapplication"
                        )
                    raw_port_start = (
                        buddy_input["port_start"]
                        if "port_start" in buddy_input
                        else args.port_start
                    )
                    if (
                        isinstance(raw_port_start, bool)
                        or not isinstance(raw_port_start, int)
                        or not 1 <= raw_port_start <= 65535
                    ):
                        raise RappHerdrError(
                            "buddy port_start must be an integer from 1 to 65535"
                        )
                    result = manager.create_buddy(
                        device_id=required_buddy_text(
                            "device_id",
                            args.device,
                        ),
                        name=required_buddy_text(
                            "name",
                            args.name,
                        ),
                        role=required_buddy_text(
                            "role",
                            args.role,
                        ),
                        ui=raw_ui,
                        port_start=raw_port_start,
                    )
                elif args.buddy_action == "list":
                    result = manager.list_buddies()
                else:
                    raw_buddy_id = (
                        buddy_input["buddy_id"]
                        if "buddy_id" in buddy_input
                        else args.buddy
                    )
                    raw_message = (
                        buddy_input["message"]
                        if "message" in buddy_input
                        else args.message
                    )
                    raw_session_id = (
                        buddy_input["session_id"]
                        if "session_id" in buddy_input
                        else args.session_id
                    )
                    if (
                        not isinstance(raw_buddy_id, str)
                        or not raw_buddy_id.strip()
                    ):
                        raise RappHerdrError(
                            "buddy buddy_id must be a non-empty string"
                        )
                    if (
                        not isinstance(raw_message, str)
                        or not raw_message.strip()
                    ):
                        raise RappHerdrError(
                            "buddy message must be a non-empty string"
                        )
                    if (
                        raw_session_id is not None
                        and (
                            not isinstance(raw_session_id, str)
                            or not raw_session_id.strip()
                        )
                    ):
                        raise RappHerdrError(
                            "buddy session_id must be a non-empty string"
                        )
                    result = manager.chat_buddy(
                        buddy_id=raw_buddy_id,
                        message=raw_message,
                        session_id=raw_session_id,
                    )
            else:
                result = manager.run(args.estate_command)
            _print(result)
            return 0 if result.get("ok") else 1
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
        if args.command == "ui":
            return run_ui(
                args.manifest,
                host=args.host,
                port=args.port,
                open_browser=args.open,
            )

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
