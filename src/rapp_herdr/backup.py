from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from .estate import ESTATE_SCHEMA, load_estate
from .model import RappHerdrError
from .receipts import ReceiptStore

BACKUP_SCHEMA = "rapp-herdr-estate-backup/1.0"
MAX_BACKUP_BYTES = 2 * 1024 * 1024


def _canonical_manifest(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _read_manifest(path: Path) -> dict[str, Any]:
    load_estate(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot export estate manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"estate manifest must contain an object: {path}")
    return value


def export_estate_backup(manifest: str | Path) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    estate = _read_manifest(manifest_path)
    canonical = _canonical_manifest(estate)
    return {
        "schema": BACKUP_SCHEMA,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "estate": estate,
    }


def _estate_from_backup(value: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict):
        raise RappHerdrError("estate backup must contain a JSON object")
    schema = value.get("schema")
    if schema != BACKUP_SCHEMA:
        raise RappHerdrError(
            f"estate backup must use schema {BACKUP_SCHEMA!r}"
        )
    estate = value.get("estate")
    if not isinstance(estate, dict):
        raise RappHerdrError("estate backup is missing its estate manifest")
    expected = value.get("manifest_sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise RappHerdrError("estate backup is missing its manifest checksum")
    actual = hashlib.sha256(_canonical_manifest(estate)).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise RappHerdrError("estate backup checksum does not match its manifest")
    return estate, BACKUP_SCHEMA


def _write_candidate(parent: Path, payload: bytes) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=parent,
        prefix=".estate-import-",
        suffix=".json",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def _rollback_path(manifest: Path) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = manifest.with_name(f"{manifest.name}.before-import-{stamp}")
    counter = 1
    while candidate.exists():
        candidate = manifest.with_name(
            f"{manifest.name}.before-import-{stamp}-{counter}"
        )
        counter += 1
    return candidate


def import_estate_backup(
    manifest: str | Path,
    value: Any,
) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    if not manifest_path.is_file():
        raise RappHerdrError(
            f"cannot replace missing estate manifest: {manifest_path}"
        )
    estate, source_schema = _estate_from_backup(value)
    return _replace_estate_manifest(
        manifest_path,
        estate,
        source_schema=source_schema,
    )


def replace_estate_manifest(
    manifest: str | Path,
    estate: dict[str, Any],
    *,
    expected_hash: str | None = None,
) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    if not manifest_path.is_file():
        raise RappHerdrError(
            f"cannot replace missing estate manifest: {manifest_path}"
        )
    if not isinstance(estate, dict) or estate.get("schema") != ESTATE_SCHEMA:
        raise RappHerdrError(
            "internal estate replacement requires a valid estate manifest"
        )
    return _replace_estate_manifest(
        manifest_path,
        estate,
        source_schema=ESTATE_SCHEMA,
        expected_hash=expected_hash,
    )


def _replace_estate_manifest(
    manifest_path: Path,
    estate: dict[str, Any],
    *,
    source_schema: str,
    expected_hash: str | None = None,
) -> dict[str, Any]:
    candidate = _write_candidate(
        manifest_path.parent,
        (json.dumps(estate, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    try:
        validated = load_estate(candidate)
        lock_digest = hashlib.sha256(
            str(manifest_path).encode()
        ).hexdigest()[:32]
        lock_path = (
            ReceiptStore().root
            / "estate-manifests"
            / f"{lock_digest}.json"
        )
        with ReceiptStore().operation_lock(lock_path, wait_timeout=30):
            current_bytes = manifest_path.read_bytes()
            current_hash = hashlib.sha256(current_bytes).hexdigest()
            if (
                expected_hash is not None
                and not hmac.compare_digest(expected_hash, current_hash)
            ):
                raise RappHerdrError(
                    "estate manifest changed before replacement"
                )
            rollback = _rollback_path(manifest_path)
            rollback_candidate = _write_candidate(
                manifest_path.parent,
                current_bytes,
            )
            os.replace(rollback_candidate, rollback)
            os.replace(candidate, manifest_path)
            manifest_path.chmod(0o600)
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise
    return {
        "ok": True,
        "estate": validated.name,
        "source_schema": source_schema,
        "previous_manifest": str(rollback),
    }
