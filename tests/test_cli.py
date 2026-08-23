from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from rapp_herdr.buddy import encode_buddy_payload
from rapp_herdr.cli import main


class BuddyCliTests(unittest.TestCase):
    def test_hidden_device_command_reads_payload_from_stdin(self) -> None:
        payload = {
            "schema": "rapp-herdr-buddy/1.0",
            "device_id": "remote",
            "message": "private message",
        }
        with patch(
            "rapp_herdr.cli.run_buddy_device",
            return_value={"ok": True},
        ) as run, patch(
            "sys.stdin",
            io.StringIO(encode_buddy_payload(payload)),
        ), redirect_stdout(io.StringIO()):
            code = main([
                "_buddy-device",
                "chat",
                "--payload-stdin",
            ])

        self.assertEqual(code, 0)
        run.assert_called_once_with("chat", payload)

    def test_create_reads_definition_from_stdin(self) -> None:
        request = {
            "device_id": "rappter-two",
            "name": "Map Maker",
            "role": "Build a visual estate map.",
            "ui": "rapplication",
            "port_start": 7300,
        }
        output = io.StringIO()
        with patch("rapp_herdr.cli.load_estate", return_value=object()), patch(
            "rapp_herdr.cli.EstateManager"
        ) as manager_type, patch(
            "sys.stdin",
            io.StringIO(json.dumps(request)),
        ), redirect_stdout(output):
            manager_type.return_value.create_buddy.return_value = {
                "ok": True,
                "presence": "online",
            }
            code = main([
                "estate",
                "buddy",
                "create",
                "/private/estate.json",
                "--stdin",
            ])

        self.assertEqual(code, 0)
        manager_type.return_value.create_buddy.assert_called_once_with(
            device_id="rappter-two",
            name="Map Maker",
            role="Build a visual estate map.",
            ui="rapplication",
            port_start=7300,
        )
        self.assertTrue(json.loads(output.getvalue())["ok"])

    def test_chat_reads_message_from_stdin(self) -> None:
        request = {
            "buddy_id": "barry",
            "message": "private message",
            "session_id": "session-1",
        }
        with patch("rapp_herdr.cli.load_estate", return_value=object()), patch(
            "rapp_herdr.cli.EstateManager"
        ) as manager_type, patch(
            "sys.stdin",
            io.StringIO(json.dumps(request)),
        ), redirect_stdout(io.StringIO()):
            manager_type.return_value.chat_buddy.return_value = {
                "ok": True,
                "response": "READY",
            }
            code = main([
                "estate",
                "buddy",
                "chat",
                "/private/estate.json",
                "--stdin",
            ])

        self.assertEqual(code, 0)
        manager_type.return_value.chat_buddy.assert_called_once_with(
            buddy_id="barry",
            message="private message",
            session_id="session-1",
        )

    def test_stdin_does_not_coerce_null_into_valid_text(self) -> None:
        error = io.StringIO()
        with patch("rapp_herdr.cli.load_estate", return_value=object()), patch(
            "rapp_herdr.cli.EstateManager"
        ) as manager_type, patch(
            "sys.stdin",
            io.StringIO(json.dumps({
                "device_id": None,
                "name": "Ghost",
                "role": "Chat.",
            })),
        ), redirect_stderr(error):
            code = main([
                "estate",
                "buddy",
                "create",
                "/private/estate.json",
                "--stdin",
            ])

        self.assertEqual(code, 1)
        manager_type.return_value.create_buddy.assert_not_called()
        self.assertIn("device_id must be a non-empty string", error.getvalue())

    def test_stdin_rejects_structured_ui_without_crashing(self) -> None:
        error = io.StringIO()
        with patch("rapp_herdr.cli.load_estate", return_value=object()), patch(
            "rapp_herdr.cli.EstateManager"
        ) as manager_type, patch(
            "sys.stdin",
            io.StringIO(json.dumps({
                "device_id": "local",
                "name": "Buddy",
                "role": "Chat.",
                "ui": [],
            })),
        ), redirect_stderr(error):
            code = main([
                "estate",
                "buddy",
                "create",
                "/private/estate.json",
                "--stdin",
            ])

        self.assertEqual(code, 1)
        manager_type.return_value.create_buddy.assert_not_called()
        self.assertIn("buddy ui must be", error.getvalue())


if __name__ == "__main__":
    unittest.main()
