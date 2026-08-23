from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import rapp_herdr.backup as backup_module
from rapp_herdr.backup import (
    BACKUP_SCHEMA,
    MAX_BACKUP_BYTES,
    BackupSizeError,
    ManifestConflictError,
    export_estate_backup,
    import_estate_backup,
    serialize_backup_envelope,
)
from rapp_herdr.model import RappHerdrError

from tests.test_estate import create_estate


def _write_manifest(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _hold_import_lock(
    manifest: str,
    acquired: multiprocessing.synchronize.Event,
    release: multiprocessing.synchronize.Event,
) -> None:
    with backup_module._ImportLock(Path(manifest), timeout=1.0):
        acquired.set()
        release.wait(timeout=5)


class EstateBackupTests(unittest.TestCase):
    def test_exact_exported_envelope_restores_and_keeps_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            envelope = export_estate_backup(manifest)
            serialized = serialize_backup_envelope(envelope)
            changed = json.loads(manifest.read_text(encoding="utf-8"))
            changed["name"] = "Changed After Export"
            _write_manifest(manifest, changed)
            immediate_predecessor = manifest.read_bytes()

            result = import_estate_backup(manifest, json.loads(serialized))

            self.assertTrue(result["ok"])
            self.assertTrue(result["committed"])
            self.assertEqual(result["source_schema"], BACKUP_SCHEMA)
            self.assertEqual(
                json.loads(manifest.read_text(encoding="utf-8"))["name"],
                "Test Estate",
            )
            rollback = Path(result["previous_manifest"])
            self.assertEqual(rollback.read_bytes(), immediate_predecessor)
            if os.name != "nt":
                self.assertEqual(rollback.stat().st_mode & 0o777, 0o600)
                self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)

    def test_plain_manifest_compatibility_is_separate_from_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            plain_manifest = json.loads(manifest.read_text(encoding="utf-8"))
            plain_manifest["name"] = "Plain Manifest Restore"

            result = import_estate_backup(manifest, plain_manifest)

            self.assertEqual(
                result["source_schema"],
                "rapp-herdr-estate/1.0",
            )
            self.assertEqual(
                json.loads(manifest.read_text(encoding="utf-8"))["name"],
                "Plain Manifest Restore",
            )

    def test_exported_backup_detects_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            backup = export_estate_backup(manifest)
            self.assertEqual(backup["schema"], BACKUP_SCHEMA)
            before = manifest.read_bytes()
            backup["estate"]["name"] = "Tampered"

            with self.assertRaisesRegex(RappHerdrError, "checksum"):
                import_estate_backup(manifest, backup)

            self.assertEqual(manifest.read_bytes(), before)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_invalid_import_never_replaces_current_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()

            with self.assertRaisesRegex(RappHerdrError, "schema"):
                import_estate_backup(
                    manifest,
                    {"schema": "not-an-estate", "devices": []},
                )

            self.assertEqual(manifest.read_bytes(), before)

    def test_oversized_serialized_envelope_is_never_exported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["padding"] = "x" * MAX_BACKUP_BYTES
            _write_manifest(manifest, value)

            with self.assertRaisesRegex(BackupSizeError, "(backup|restore) limit"):
                export_estate_backup(manifest)

    def test_export_validates_and_serializes_one_descriptor_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            original_write_candidate = backup_module._write_candidate

            def replace_path_after_snapshot(
                parent: Path,
                payload: bytes,
            ) -> Path:
                candidate = original_write_candidate(parent, payload)
                manifest.write_text(
                    '{"schema":"concurrent-invalid-generation"}\n',
                    encoding="utf-8",
                )
                return candidate

            with patch.object(
                backup_module,
                "_write_candidate",
                side_effect=replace_path_after_snapshot,
            ):
                envelope = export_estate_backup(manifest)

            self.assertEqual(envelope["estate"]["name"], "Test Estate")
            with tempfile.TemporaryDirectory() as restore_directory:
                restore = create_estate(
                    Path(restore_directory) / "estate.json"
                )
                result = import_estate_backup(restore, envelope)
                self.assertTrue(result["committed"])

    def test_pretty_serialization_expansion_is_bounded_before_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            value = json.loads(manifest.read_text(encoding="utf-8"))
            nested: object = {"values": [0] * 3000}
            for _index in range(500):
                nested = {"x": nested}
            value["compact_but_deep"] = nested
            compact = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.assertLess(len(compact), MAX_BACKUP_BYTES)

            with (
                patch.object(
                    backup_module,
                    "_write_candidate",
                    side_effect=AssertionError("candidate must not be written"),
                ),
                self.assertRaisesRegex(BackupSizeError, "(backup|restore) limit"),
            ):
                import_estate_backup(manifest, value)

            self.assertEqual(
                json.loads(manifest.read_text(encoding="utf-8"))["name"],
                "Test Estate",
            )

    def test_concurrent_imports_each_capture_immediate_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            original_write_candidate = backup_module._write_candidate
            original_rollback_path = backup_module._rollback_path
            start_barrier = threading.Barrier(2)
            thread_state = threading.local()

            def aligned_write_candidate(parent: Path, payload: bytes) -> Path:
                candidate = original_write_candidate(parent, payload)
                if not getattr(thread_state, "aligned", False):
                    thread_state.aligned = True
                    start_barrier.wait(timeout=3)
                return candidate

            def slow_rollback_path(path: Path) -> Path:
                time.sleep(0.1)
                return original_rollback_path(path)

            base = json.loads(manifest.read_text(encoding="utf-8"))
            first = {**base, "name": "Concurrent A"}
            second = {**base, "name": "Concurrent B"}
            with (
                patch.object(
                    backup_module,
                    "_write_candidate",
                    side_effect=aligned_write_candidate,
                ),
                patch.object(
                    backup_module,
                    "_rollback_path",
                    side_effect=slow_rollback_path,
                ),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                results = list(
                    executor.map(
                        lambda value: import_estate_backup(manifest, value),
                        (first, second),
                    )
                )

            rollback_names = [
                json.loads(
                    Path(result["previous_manifest"]).read_text(
                        encoding="utf-8"
                    )
                )["name"]
                for result in results
            ]
            final_name = json.loads(
                manifest.read_text(encoding="utf-8")
            )["name"]
            self.assertCountEqual(
                [*rollback_names, final_name],
                ["Test Estate", "Concurrent A", "Concurrent B"],
            )

    def test_dead_process_lock_is_reaped_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            lock_path = manifest.with_name(f".{manifest.name}.import.lock")
            lock_path.mkdir()
            (lock_path / "owner.json").write_text(
                json.dumps(
                    {
                        "pid": 2**30,
                        "token": "crashed-owner",
                        "created_at": time.time(),
                    }
                ),
                encoding="utf-8",
            )
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Recovered Lock"

            result = import_estate_backup(manifest, value)

            self.assertTrue(result["ok"])
            self.assertFalse(lock_path.exists())

    def test_stale_ownerless_lock_is_quarantined_and_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            lock_path = manifest.with_name(f".{manifest.name}.import.lock")
            lock_path.mkdir()
            stale = time.time() - 3600
            os.utime(lock_path, (stale, stale))
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Recovered Ownerless Lock"

            result = import_estate_backup(manifest, value)

            self.assertTrue(result["ok"])
            self.assertFalse(lock_path.exists())
            self.assertEqual(
                list(manifest.parent.glob(f"{lock_path.name}.stale-*")),
                [],
            )

    def test_fresh_ownerless_lock_is_not_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            lock_path = manifest.with_name(f".{manifest.name}.import.lock")
            lock_path.mkdir()
            contender = backup_module._ImportLock(
                manifest,
                timeout=0.03,
                stale_after=60,
            )

            with self.assertRaisesRegex(RappHerdrError, "timed out"):
                contender.acquire()

            self.assertTrue(lock_path.is_dir())

    def test_stale_malformed_owner_is_quarantined_and_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            lock_path = manifest.with_name(f".{manifest.name}.import.lock")
            owner_path = lock_path / "owner.json"
            lock_path.mkdir()
            owner_path.write_text('{"pid":', encoding="utf-8")
            stale = time.time() - 3600
            os.utime(owner_path, (stale, stale))
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Recovered Malformed Owner"

            result = import_estate_backup(manifest, value)

            self.assertTrue(result["ok"])
            self.assertFalse(lock_path.exists())
            self.assertEqual(
                list(manifest.parent.glob(f"{lock_path.name}.stale-*")),
                [],
            )

    def test_live_process_lock_wait_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            owner = backup_module._ImportLock(manifest, timeout=0.2)
            contender = backup_module._ImportLock(manifest, timeout=0.05)

            with owner:
                started = time.monotonic()
                with self.assertRaisesRegex(RappHerdrError, "timed out"):
                    contender.acquire()
                elapsed = time.monotonic() - started

            self.assertGreaterEqual(elapsed, 0.04)
            self.assertLess(elapsed, 0.5)

    def test_reused_pid_identity_does_not_strand_stale_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            contender = backup_module._ImportLock(
                manifest,
                timeout=0.2,
                stale_after=0.0,
            )
            contender.path.mkdir()
            contender.owner_path.write_text(
                json.dumps(
                    {
                        "pid": 4321,
                        "token": "crashed-owner",
                        "created_at": time.time() - 3600,
                        "process_identity": "old-process-start",
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch.object(backup_module, "_process_exists", return_value=True),
                patch.object(
                    backup_module,
                    "_process_start_identity",
                    return_value="reused-pid-new-start",
                ),
            ):
                self.assertTrue(contender._reap_if_stale())

            self.assertFalse(contender.path.exists())

    def test_live_pid_lock_is_not_reaped_when_heartbeat_looks_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            lock_path = manifest.with_name(f".{manifest.name}.import.lock")
            owner_path = lock_path / "owner.json"
            lock_path.mkdir()
            owner_path.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "token": "suspended-live-owner",
                        "created_at": time.time() - 3600,
                    }
                ),
                encoding="utf-8",
            )
            stale = time.time() - 3600
            os.utime(owner_path, (stale, stale))
            contender = backup_module._ImportLock(
                manifest,
                timeout=0.03,
                stale_after=0.001,
            )

            with self.assertRaisesRegex(RappHerdrError, "timed out"):
                contender.acquire()

            self.assertTrue(lock_path.is_dir())
            self.assertEqual(
                json.loads(owner_path.read_text(encoding="utf-8"))["token"],
                "suspended-live-owner",
            )

    def test_lock_is_not_reaped_when_pid_identity_is_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            lock_path = manifest.with_name(f".{manifest.name}.import.lock")
            owner_path = lock_path / "owner.json"
            lock_path.mkdir()
            owner_path.write_text(
                json.dumps(
                    {
                        "pid": 424242,
                        "token": "identity-cannot-be-proven",
                        "created_at": time.time() - 3600,
                    }
                ),
                encoding="utf-8",
            )
            stale = time.time() - 3600
            os.utime(owner_path, (stale, stale))
            contender = backup_module._ImportLock(
                manifest,
                timeout=0.03,
                stale_after=0.001,
            )

            with (
                patch.object(
                    backup_module,
                    "_process_exists",
                    return_value=None,
                ),
                self.assertRaisesRegex(RappHerdrError, "timed out"),
            ):
                contender.acquire()

            self.assertTrue(lock_path.is_dir())

    def test_import_waits_for_lock_held_by_another_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json").resolve()
            context = multiprocessing.get_context("spawn")
            acquired = context.Event()
            release = context.Event()
            process = context.Process(
                target=_hold_import_lock,
                args=(str(manifest), acquired, release),
            )
            process.start()
            timer: threading.Timer | None = None
            try:
                self.assertTrue(acquired.wait(timeout=3))
                value = json.loads(manifest.read_text(encoding="utf-8"))
                value["name"] = "Cross Process Import"
                timer = threading.Timer(0.15, release.set)
                timer.start()
                started = time.monotonic()

                result = import_estate_backup(manifest, value)

                self.assertGreaterEqual(time.monotonic() - started, 0.1)
                self.assertTrue(result["ok"])
            finally:
                release.set()
                if timer is not None:
                    timer.join(timeout=1)
                process.join(timeout=3)
            self.assertEqual(process.exitcode, 0)

    def test_permission_failure_before_commit_preserves_current_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Must Not Commit"

            with (
                patch.object(
                    backup_module,
                    "_set_private_mode",
                    side_effect=PermissionError("permission denied"),
                ),
                self.assertRaisesRegex(RappHerdrError, "permission denied"),
            ):
                import_estate_backup(manifest, value)

            self.assertEqual(manifest.read_bytes(), before)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_stolen_fencing_token_blocks_authoritative_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Must Not Commit After Token Theft"
            real_rollback_path = backup_module._rollback_path

            def choose_rollback_then_steal(path: Path) -> Path:
                owner_path = (
                    manifest.parent
                    / f".{manifest.name}.import.lock"
                    / "owner.json"
                )
                owner = json.loads(owner_path.read_text(encoding="utf-8"))
                owner["token"] = "new-fenced-owner"
                owner_path.write_text(json.dumps(owner), encoding="utf-8")
                return real_rollback_path(path)

            with (
                patch.object(
                    backup_module,
                    "_rollback_path",
                    side_effect=choose_rollback_then_steal,
                ),
                self.assertRaisesRegex(RappHerdrError, "ownership was lost"),
            ):
                import_estate_backup(manifest, value)

            self.assertEqual(manifest.read_bytes(), before)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_operator_update_at_atomic_commit_is_restored_and_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Import Must Not Win"
            operator_value = {**value, "name": "Operator Commit-Time Update"}
            operator_payload = (
                json.dumps(operator_value, ensure_ascii=False, indent=2) + "\n"
            ).encode("utf-8")
            real_replace_with_backup = (
                backup_module._platform_replace_with_backup
            )

            def update_then_commit(
                target: Path,
                candidate: Path,
                rollback: Path,
            ) -> None:
                target.write_bytes(operator_payload)
                real_replace_with_backup(
                    target,
                    candidate,
                    rollback,
                )

            with (
                patch.object(
                    backup_module,
                    "_platform_replace_with_backup",
                    side_effect=update_then_commit,
                ),
                self.assertRaisesRegex(
                    ManifestConflictError,
                    "concurrent update was restored",
                ),
            ):
                import_estate_backup(manifest, value)

            self.assertEqual(manifest.read_bytes(), operator_payload)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_unsupported_atomic_commit_mechanism_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Must Not Use A Weaker Rename"

            with (
                patch.object(
                    backup_module,
                    "_platform_replace_with_backup",
                    side_effect=backup_module.AtomicCommitUnavailableError(
                        "atomic exchange unsupported"
                    ),
                ),
                self.assertRaisesRegex(
                    RappHerdrError,
                    "atomic exchange unsupported",
                ),
            ):
                import_estate_backup(manifest, value)

            self.assertEqual(manifest.read_bytes(), before)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_ambiguous_source_consumed_without_destination_change_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Must Not Be Reported Committed"

            def consume_source_then_fail(
                _target: Path,
                candidate: Path,
                _rollback: Path,
            ) -> None:
                candidate.unlink()
                raise PermissionError("source consumed without commit")

            with (
                patch.object(
                    backup_module,
                    "_platform_replace_with_backup",
                    side_effect=consume_source_then_fail,
                ),
                self.assertRaisesRegex(
                    RappHerdrError,
                    "source consumed without commit",
                ),
            ):
                import_estate_backup(manifest, value)

            self.assertEqual(manifest.read_bytes(), before)
            self.assertEqual(
                list(manifest.parent.glob("estate.json.before-import-*")),
                [],
            )

    def test_commit_point_error_after_rename_reports_committed_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            before = manifest.read_bytes()
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["name"] = "Committed Estate"
            real_replace_with_backup = (
                backup_module._platform_replace_with_backup
            )

            def replace_then_report_error(
                target: Path,
                candidate: Path,
                rollback: Path,
            ) -> None:
                real_replace_with_backup(target, candidate, rollback)
                raise PermissionError("late filesystem report")

            with patch.object(
                backup_module,
                "_platform_replace_with_backup",
                side_effect=replace_then_report_error,
            ):
                result = import_estate_backup(manifest, value)

            self.assertTrue(result["ok"])
            self.assertTrue(result["committed"])
            self.assertIn("late filesystem report", result["warning"])
            self.assertEqual(
                json.loads(manifest.read_text(encoding="utf-8"))["name"],
                "Committed Estate",
            )
            self.assertEqual(
                Path(result["previous_manifest"]).read_bytes(),
                before,
            )

    def test_post_exchange_superseding_write_is_reported_as_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_estate(Path(directory) / "estate.json")
            imported = json.loads(manifest.read_text(encoding="utf-8"))
            imported["name"] = "Imported Estate"
            concurrent = {**imported, "name": "Concurrent Operator Estate"}
            concurrent_payload = (
                json.dumps(concurrent, ensure_ascii=False, indent=2) + "\n"
            ).encode("utf-8")
            real_commit = backup_module._platform_replace_with_backup

            def commit_then_supersede(
                manifest_path: Path,
                candidate: Path,
                rollback: Path,
            ) -> None:
                real_commit(manifest_path, candidate, rollback)
                manifest_path.write_bytes(concurrent_payload)

            with (
                patch.object(
                    backup_module,
                    "_platform_replace_with_backup",
                    side_effect=commit_then_supersede,
                ),
                self.assertRaisesRegex(
                    backup_module.ManifestConflictError,
                    "superseded",
                ),
            ):
                import_estate_backup(manifest, imported)

            self.assertEqual(manifest.read_bytes(), concurrent_payload)


if __name__ == "__main__":
    unittest.main()
