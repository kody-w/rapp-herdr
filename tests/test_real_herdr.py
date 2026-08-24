from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from tests.helpers import create_neighborhood, create_twin
from tests.test_catalog import create_catalog


def _request_json(url: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            return int(exc.code), json.loads(exc.read())
        finally:
            exc.close()


@unittest.skipUnless(
    os.environ.get("RAPP_HERDR_E2E") == "1",
    "set RAPP_HERDR_E2E=1 to exercise an installed Herdr server",
)
class RealHerdrTests(unittest.TestCase):
    def test_four_twin_neighborhood_lifecycle(self) -> None:
        herdr = shutil.which("herdr")
        self.assertIsNotNone(herdr)
        brainstem_python = Path.home() / ".brainstem" / "venv" / "bin" / "python"
        if os.name == "nt":
            brainstem_python = (
                Path.home() / ".brainstem" / "venv" / "Scripts" / "python.exe"
            )
        self.assertTrue(brainstem_python.is_file())
        session = f"rapp-herdr-e2e-{uuid.uuid4().hex[:8]}"
        source_root = Path(__file__).resolve().parents[1] / "src"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source_root)
        server = subprocess.Popen(
            [herdr, "--session", session, "server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = subprocess.run(
                    [herdr, "--session", session, "status"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if status.returncode == 0 and "status: running" in status.stdout:
                    break
                time.sleep(0.1)
            else:
                self.fail("isolated Herdr server did not start")

            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, rappids = create_neighborhood(root / "neighborhood")
                estate = root / "estate"
                app_source = """
import os
import time
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.post("/chat")
def chat():
    data = request.get_json(force=True) or {}
    if data.get("sleep"):
        time.sleep(float(data["sleep"]))
    if data.get("fail"):
        return jsonify({"error": "injected"}), 500
    return jsonify({
        "response": data.get("user_input", ""),
        "agent_logs": [],
        "session_id": data.get("session_id", "test"),
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ["PORT"]), debug=False)
"""
                for index, rappid in enumerate(rappids, 1):
                    workspace = create_twin(estate, f"twin-{index}", rappid)
                    (workspace / "brainstem.py").write_text(
                        app_source, encoding="utf-8"
                    )
                    utils = workspace / "utils"
                    utils.mkdir()
                    (utils / "boot.py").write_text(
                        "raise SystemExit(78)\n",
                        encoding="utf-8",
                    )

                command = [
                    sys.executable,
                    "-m",
                    "rapp_herdr",
                    "neighborhood",
                    "up",
                    str(manifest),
                    "--estate-root",
                    str(estate),
                    "--require-all-local",
                    "--session",
                    session,
                    "--brainstem-python",
                    str(brainstem_python),
                    "--no-bootstrap",
                    "--receipt-root",
                    str(root / "state"),
                    "--base-port",
                    "7181",
                ]
                phase_started = time.monotonic()
                up = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=120,
                    check=False,
                )
                self.assertEqual(up.returncode, 0, up.stderr or up.stdout)
                print(f"\n[e2e] neighborhood up: {time.monotonic() - phase_started:.2f}s")
                self.assertLess(time.monotonic() - phase_started, 30)
                result = json.loads(up.stdout)
                self.assertTrue(result["managed"])
                self.assertEqual(len(result["members"]), 4)

                deadline = time.monotonic() + 40
                agent_values = []
                while time.monotonic() < deadline:
                    agents = subprocess.run(
                        [herdr, "--session", session, "agent", "list"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=True,
                    )
                    agent_values = json.loads(agents.stdout)["result"]["agents"]
                    states = {agent["agent_status"] for agent in agent_values}
                    if len(agent_values) == 4 and states <= {"idle", "done"}:
                        break
                    time.sleep(0.1)
                self.assertEqual(len(agent_values), 4)
                self.assertTrue(
                    {agent["agent_status"] for agent in agent_values}
                    <= {"idle", "done"}
                )

                first_url = result["members"][0]["url"]
                response_holder = {}

                def slow_chat() -> None:
                    response_holder["value"] = _request_json(
                        f"{first_url}/chat",
                        {"user_input": "slow", "sleep": 1},
                    )

                thread = threading.Thread(target=slow_chat)
                thread.start()
                deadline = time.monotonic() + 5
                saw_working = False
                while time.monotonic() < deadline:
                    current = subprocess.run(
                        [herdr, "--session", session, "agent", "list"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=True,
                    )
                    values = json.loads(current.stdout)["result"]["agents"]
                    if any(agent["agent_status"] == "working" for agent in values):
                        saw_working = True
                        break
                    time.sleep(0.05)
                thread.join(timeout=5)
                self.assertTrue(saw_working)
                self.assertEqual(response_holder["value"][0], 200)

                status_code, _ = _request_json(
                    f"{first_url}/chat", {"user_input": "fail", "fail": True}
                )
                self.assertEqual(status_code, 500)
                blocked = subprocess.run(
                    [herdr, "--session", session, "agent", "list"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                blocked_values = json.loads(blocked.stdout)["result"]["agents"]
                self.assertIn(
                    "blocked",
                    {agent["agent_status"] for agent in blocked_values},
                )

                recovered_code, _ = _request_json(
                    f"{first_url}/chat", {"user_input": "recovered"}
                )
                self.assertEqual(recovered_code, 200)

                phase_started = time.monotonic()
                down = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "rapp_herdr",
                        "neighborhood",
                        "down",
                        str(manifest),
                        "--session",
                        session,
                        "--receipt-root",
                        str(root / "state"),
                    ],
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(down.returncode, 0, down.stderr or down.stdout)
                print(f"[e2e] neighborhood down: {time.monotonic() - phase_started:.2f}s")
                self.assertEqual(json.loads(down.stdout)["state"], "down")

                catalogs_root = root / "catalogs"
                create_catalog(catalogs_root)
                estate_manifest = root / "estate.json"
                estate_manifest.write_text(
                    json.dumps(
                        {
                            "schema": "rapp-herdr-estate/1.0",
                            "name": "E2E Estate",
                            "devices": [
                                {
                                    "id": "local",
                                    "transport": "local",
                                    "os": "posix",
                                    "session": session,
                                    "herdr_bin": herdr,
                                    "rapp_herdr_bin": sys.executable,
                                    "receipt_root": str(root / "catalog-state"),
                                    "inventory_roots": [str(root / "empty-twins")],
                                    "catalog_roots": [str(catalogs_root)],
                                    "neighborhoods": [],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                estate_up = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "rapp_herdr",
                        "estate",
                        "up",
                        str(estate_manifest),
                    ],
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(
                    estate_up.returncode,
                    0,
                    estate_up.stderr or estate_up.stdout,
                )
                estate_agents = subprocess.run(
                    [herdr, "--session", session, "agent", "list"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                catalog_agents = json.loads(estate_agents.stdout)["result"]["agents"]
                self.assertEqual(len(catalog_agents), 1)
                self.assertEqual(catalog_agents[0]["agent"], "rapp-neighborhood")
                catalog_pane = catalog_agents[0]["pane_id"]
                try:
                    subprocess.run(
                        [
                            herdr,
                            "--session",
                            session,
                            "pane",
                            "run",
                            catalog_pane,
                            "hello",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=True,
                    )
                    waited = subprocess.run(
                        [
                            herdr,
                            "--session",
                            session,
                            "pane",
                            "wait-output",
                            catalog_pane,
                            "--match",
                            "neighborhood:hello",
                            "--timeout",
                            "10000",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertEqual(
                        waited.returncode,
                        0,
                        waited.stderr or waited.stdout,
                    )
                finally:
                    estate_down = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "rapp_herdr",
                            "estate",
                            "down",
                            str(estate_manifest),
                        ],
                        capture_output=True,
                        text=True,
                        env=environment,
                        timeout=30,
                        check=False,
                    )
                self.assertEqual(
                    estate_down.returncode,
                    0,
                    estate_down.stderr or estate_down.stdout,
                )
        finally:
            subprocess.run(
                [herdr, "--session", session, "server", "stop"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.terminate()
                server.wait(timeout=5)
            subprocess.run(
                [herdr, "session", "delete", session, "--json"],
                capture_output=True,
                timeout=10,
                check=False,
            )


if __name__ == "__main__":
    unittest.main()
