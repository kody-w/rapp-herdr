from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import rapp_herdr.backup as backup_module
from rapp_herdr.bootstrap import _is_persistence_probe
from rapp_herdr.model import RappHerdrError
from rapp_herdr.probe import (
    PROBE_EVIDENCE_SCHEMA,
    PROBE_MANIFEST_UPDATE_RETRIES,
    PROBE_NEIGHBORHOOD_NAME,
    PROBE_SCHEMA,
    PROBE_STRICT_RUNTIME_STATE_CAPABILITY,
    add_probe_neighborhoods,
    probe_payload,
    probe_rappid,
    run_probe_device,
    validate_probe_response,
)
from rapp_herdr.version import __version__
from tests.test_estate import create_estate


class PersistenceProbeTests(unittest.TestCase):
    def test_probe_evidence_rejects_mismatched_implementation_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = probe_payload(
                "device-one",
                str(Path(directory) / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    Path(directory) / "neighborhood" / "neighborhood.json"
                ),
            )
            response = run_probe_device("seed", payload)
            response["evidence"]["implementation"]["version"] = "0.0.0"

            with self.assertRaisesRegex(RappHerdrError, "version does not match"):
                validate_probe_response(
                    response,
                    action="seed",
                    device_id="device-one",
                )

    def test_only_managed_probe_marker_enables_lightweight_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = (
                Path(directory)
                / "rapp-herdr-persistence-probe-device-one"
            )
            workspace.mkdir()
            rappid = probe_rappid("device-one")
            arguments = {
                "rappid": rappid,
                "neighborhood": PROBE_NEIGHBORHOOD_NAME,
                "entrypoint": "brainstem.py",
            }
            self.assertFalse(_is_persistence_probe(workspace, **arguments))
            (workspace / ".rapp-herdr-probe.json").write_text(
                json.dumps(
                    {
                        "schema": PROBE_SCHEMA,
                        "device_id": "device-one",
                        "rappid": rappid,
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(_is_persistence_probe(workspace, **arguments))
            self.assertFalse(
                _is_persistence_probe(
                    workspace,
                    **{**arguments, "rappid": probe_rappid("other-device")},
                )
            )

    def test_seed_is_isolated_idempotent_and_preserves_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )

            first = run_probe_device("seed", payload)
            state_path = (
                Path(first["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            state = json.loads(state_path.read_text())
            state["message_count"] = 1
            state["messages"] = [
                {
                    "content": "already stored",
                    "recorded_at": "2026-08-23T19:00:00Z",
                }
            ]
            state_path.write_text(json.dumps(state))

            second = run_probe_device("seed", payload)

            self.assertTrue(second["ok"])
            self.assertEqual(
                json.loads(state_path.read_text())["message_count"],
                1,
            )
            self.assertEqual(second["state"]["messages"][0]["content"], "already stored")
            self.assertTrue((Path(first["workspace"]) / "brainstem.py").is_file())
            self.assertFalse(
                (Path(first["workspace"]) / "requirements.txt").exists()
            )
            compile(
                (Path(first["workspace"]) / "brainstem.py").read_text(),
                "brainstem.py",
                "exec",
            )

    def test_seed_rejects_malformed_and_non_object_existing_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            state_path = (
                Path(seeded["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )

            for raw in ("{malformed", "[]"):
                with self.subTest(raw=raw):
                    state_path.write_text(raw, encoding="utf-8")
                    with self.assertRaises(RappHerdrError):
                        run_probe_device("seed", payload)

    def test_seed_validates_every_owned_state_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            state_path = (
                Path(seeded["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            mutations = {
                "schema": "wrong",
                "device_id": "wrong",
                "rappid": "wrong",
                "survival_marker": "wrong",
                "boot_count": -1,
                "message_count": False,
                "messages": {},
            }

            for field, replacement in mutations.items():
                with self.subTest(field=field):
                    state = json.loads(json.dumps(seeded["state"]))
                    state[field] = replacement
                    state_path.write_text(json.dumps(state), encoding="utf-8")
                    with self.assertRaises(RappHerdrError):
                        run_probe_device("seed", payload)

    @unittest.skipIf(os.name == "nt", "symlink setup is POSIX-specific")
    def test_seed_rejects_state_parent_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            workspace = Path(seeded["workspace"])
            state_directory = workspace / ".brainstem_data"
            (state_directory / "persistence_probe.json").unlink()
            state_directory.rmdir()
            outside = root / "outside"
            outside.mkdir()
            state_directory.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(RappHerdrError, "escapes"):
                run_probe_device("seed", payload)

            self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "symlink setup is POSIX-specific")
    def test_mark_rejects_symlink_escape_before_contacting_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                message="do not write outside",
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            workspace = Path(seeded["workspace"])
            outside_mark = root / "outside-mark.json"
            outside_mark.write_text("unchanged", encoding="utf-8")
            (workspace / ".rapp-herdr-probe-mark.json").symlink_to(outside_mark)

            with patch("rapp_herdr.probe._request_json") as request:
                with self.assertRaisesRegex(RappHerdrError, "escapes"):
                    run_probe_device("mark", payload)

            request.assert_not_called()
            self.assertEqual(outside_mark.read_text(encoding="utf-8"), "unchanged")

    def test_seed_refuses_an_unmanaged_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = (
                root / "twins" / "rapp-herdr-persistence-probe-device-one"
            )
            workspace.mkdir(parents=True)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )

            with self.assertRaisesRegex(RappHerdrError, "unmanaged"):
                run_probe_device("seed", payload)

    def test_mark_and_verify_require_matching_persistent_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                message="survive this",
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            state_path = (
                Path(seeded["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            marked_state = {
                **seeded["state"],
                "boot_count": 1,
                "message_count": 1,
                "messages": [
                    {
                        "content": "survive this",
                        "recorded_at": "2026-08-23T19:00:00Z",
                    }
                ],
            }
            state_path.write_text(json.dumps(marked_state), encoding="utf-8")

            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": marked_state},
            ):
                marked = run_probe_device("mark", payload)
                with self.assertRaisesRegex(RappHerdrError, "not restarted"):
                    run_probe_device("verify", payload)

            restarted_state = {**marked_state, "boot_count": 2}
            state_path.write_text(json.dumps(restarted_state), encoding="utf-8")
            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": restarted_state},
            ):
                verified = run_probe_device("verify", payload)

            self.assertEqual(
                marked["state"]["survival_marker"],
                verified["state"]["survival_marker"],
            )
            self.assertEqual(verified["state"]["message_count"], 1)
            for action, result in (
                ("seed", seeded),
                ("mark", marked),
                ("verify", verified),
            ):
                with self.subTest(action=action):
                    self.assertEqual(result["action"], action)
                    self.assertEqual(result["device"], "device-one")
                    self.assertEqual(
                        result["evidence"]["schema"],
                        PROBE_EVIDENCE_SCHEMA,
                    )
                    self.assertEqual(
                        result["evidence"]["action"],
                        action,
                    )
                    self.assertEqual(
                        result["evidence"]["device"],
                        "device-one",
                    )
                    self.assertIn(
                        PROBE_STRICT_RUNTIME_STATE_CAPABILITY,
                        result["evidence"]["capabilities"],
                    )
                    self.assertEqual(
                        result["evidence"]["implementation"]["name"],
                        "rapp-herdr",
                    )
                    self.assertEqual(
                        result["evidence"]["implementation"]["version"],
                        __version__,
                    )

    def test_verify_fails_when_runtime_state_is_incomplete_or_divergent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                message="survive this",
                neighborhood_manifest=str(
                    root / "neighborhood" / "neighborhood.json"
                ),
            )
            seeded = run_probe_device("seed", payload)
            state_path = (
                Path(seeded["workspace"])
                / ".brainstem_data"
                / "persistence_probe.json"
            )
            marked_state = {
                **seeded["state"],
                "boot_count": 1,
                "message_count": 1,
                "messages": [
                    {
                        "content": "survive this",
                        "recorded_at": "2026-08-23T19:00:00Z",
                    }
                ],
            }
            state_path.write_text(json.dumps(marked_state), encoding="utf-8")
            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": marked_state},
            ):
                run_probe_device("mark", payload)

            restarted_state = {**marked_state, "boot_count": 2}
            state_path.write_text(json.dumps(restarted_state), encoding="utf-8")
            incomplete = dict(restarted_state)
            incomplete.pop("message_count")
            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": incomplete},
            ), self.assertRaisesRegex(RappHerdrError, "message_count"):
                run_probe_device("verify", payload)

            divergent = {**restarted_state, "boot_count": 3}
            with patch(
                "rapp_herdr.probe._request_json",
                return_value={"probe": divergent},
            ), self.assertRaisesRegex(RappHerdrError, "runtime and disk"):
                run_probe_device("verify", payload)

    def test_seed_refuses_an_unmanaged_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            neighborhood = root / "neighborhood"
            neighborhood.mkdir()
            (neighborhood / "neighborhood.json").write_text(
                json.dumps({"schema": "someone-elses-neighborhood/1.0"}),
                encoding="utf-8",
            )
            payload = probe_payload(
                "device-one",
                str(root / "twins"),
                base_port=7199,
                neighborhood_manifest=str(
                    neighborhood / "neighborhood.json"
                ),
            )

            with self.assertRaisesRegex(RappHerdrError, "unmanaged"):
                run_probe_device("seed", payload)

    def test_estate_manifest_adds_only_managed_probe_neighborhoods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")

            result = add_probe_neighborhoods(
                manifest,
                {"local", "remote-mac"},
                base_port=7199,
            )

            self.assertTrue(result["changed"])
            updated = json.loads(manifest.read_text())
            for device in updated["devices"]:
                probe = device["neighborhoods"][-1]
                self.assertEqual(probe["managed_by"], PROBE_SCHEMA)
                self.assertEqual(probe["base_port"], 7199)
                self.assertIn(".brainstem/venv", probe["brainstem_python"])
                self.assertFalse(probe["bootstrap"])
            self.assertTrue(Path(result["previous_manifest"]).is_file())

    def test_probe_neighborhood_update_retries_without_losing_operator_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            real_import = backup_module.import_estate_backup
            attempts = 0

            def import_after_operator_change(path, value, **kwargs):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    operator_value = json.loads(
                        manifest.read_text(encoding="utf-8")
                    )
                    operator_value["devices"][0]["note"] = (
                        "concurrent operator edit"
                    )
                    real_import(manifest, operator_value)
                return real_import(path, value, **kwargs)

            with patch.object(
                backup_module,
                "import_estate_backup",
                side_effect=import_after_operator_change,
            ):
                result = add_probe_neighborhoods(
                    manifest,
                    {"local"},
                    base_port=7199,
                )

            updated = json.loads(manifest.read_text(encoding="utf-8"))
            local = updated["devices"][0]
            self.assertEqual(attempts, 2)
            self.assertTrue(result["changed"])
            self.assertEqual(local["note"], "concurrent operator edit")
            self.assertEqual(
                local["neighborhoods"][-1]["managed_by"],
                PROBE_SCHEMA,
            )

    def test_probe_neighborhood_update_has_bounded_conflict_retries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            conflict = backup_module.ManifestConflictError("raced")

            with (
                patch.object(
                    backup_module,
                    "import_estate_backup",
                    side_effect=conflict,
                ) as importer,
                self.assertRaisesRegex(RappHerdrError, "4 attempts"),
            ):
                add_probe_neighborhoods(
                    manifest,
                    {"local"},
                    base_port=7199,
                )

            self.assertEqual(
                importer.call_count,
                PROBE_MANIFEST_UPDATE_RETRIES,
            )


if __name__ == "__main__":
    unittest.main()
