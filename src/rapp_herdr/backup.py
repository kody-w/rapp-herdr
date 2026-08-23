from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .estate import ESTATE_SCHEMA, load_estate
from .model import RappHerdrError

BACKUP_SCHEMA = "rapp-herdr-estate-backup/1.0"
MAX_BACKUP_BYTES = 2 * 1024 * 1024
IMPORT_LOCK_TIMEOUT_SECONDS = 5.0
IMPORT_LOCK_STALE_SECONDS = 30.0
IMPORT_LOCK_POLL_SECONDS = 0.05


class BackupSizeError(RappHerdrError):
    pass


class ManifestConflictError(RappHerdrError):
    pass


class AtomicCommitUnavailableError(RappHerdrError):
    pass


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


def _bounded_pretty_json(value: Any, description: str) -> bytes:
    payload = bytearray()
    markers: set[int] = set()

    def emit(text: str) -> None:
        for offset in range(0, len(text), 4096):
            encoded = text[offset : offset + 4096].encode("utf-8")
            if len(payload) + len(encoded) > MAX_BACKUP_BYTES:
                raise BackupSizeError(
                    f"{description} exceeds the "
                    f"{MAX_BACKUP_BYTES}-byte restore limit"
                )
            payload.extend(encoded)

    def emit_string(text: str) -> None:
        emit('"')
        for offset in range(0, len(text), 4096):
            escaped = json.encoder.encode_basestring(
                text[offset : offset + 4096]
            )
            emit(escaped[1:-1])
        emit('"')

    def key_text(key: Any) -> str:
        if isinstance(key, str):
            return key
        if key is True:
            return "true"
        if key is False:
            return "false"
        if key is None:
            return "null"
        if isinstance(key, int):
            return str(key)
        if isinstance(key, float):
            return json.dumps(key, ensure_ascii=False)
        raise TypeError(
            "keys must be str, int, float, bool or None, "
            f"not {type(key).__name__}"
        )

    def encode(current: Any, level: int) -> None:
        if isinstance(current, str):
            emit_string(current)
            return
        if current is None:
            emit("null")
            return
        if current is True:
            emit("true")
            return
        if current is False:
            emit("false")
            return
        if isinstance(current, (int, float)):
            emit(json.dumps(current, ensure_ascii=False))
            return
        if isinstance(current, dict):
            if not current:
                emit("{}")
                return
            marker = id(current)
            if marker in markers:
                raise ValueError("Circular reference detected")
            markers.add(marker)
            try:
                emit("{\n")
                for index, (key, item) in enumerate(current.items()):
                    if index:
                        emit(",\n")
                    emit("  " * (level + 1))
                    emit_string(key_text(key))
                    emit(": ")
                    encode(item, level + 1)
                emit("\n")
                emit("  " * level)
                emit("}")
            finally:
                markers.remove(marker)
            return
        if isinstance(current, (list, tuple)):
            if not current:
                emit("[]")
                return
            marker = id(current)
            if marker in markers:
                raise ValueError("Circular reference detected")
            markers.add(marker)
            try:
                emit("[\n")
                for index, item in enumerate(current):
                    if index:
                        emit(",\n")
                    emit("  " * (level + 1))
                    encode(item, level + 1)
                emit("\n")
                emit("  " * level)
                emit("]")
            finally:
                markers.remove(marker)
            return
        raise TypeError(
            f"Object of type {type(current).__name__} is not JSON serializable"
        )

    try:
        encode(value, 0)
        emit("\n")
    except BackupSizeError:
        raise
    except (
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise RappHerdrError(f"cannot serialize {description}: {exc}") from exc
    return bytes(payload)


def serialize_backup_envelope(value: dict[str, Any]) -> bytes:
    if not isinstance(value, dict) or value.get("schema") != BACKUP_SCHEMA:
        raise RappHerdrError(
            f"backup envelope must use schema {BACKUP_SCHEMA!r}"
        )
    return _bounded_pretty_json(value, "serialized backup envelope")


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_BACKUP_BYTES + 1)
    except OSError as exc:
        raise RappHerdrError(f"cannot read estate manifest {path}: {exc}") from exc
    if len(payload) > MAX_BACKUP_BYTES:
        raise BackupSizeError(
            f"estate manifest exceeds the {MAX_BACKUP_BYTES}-byte backup limit"
        )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RappHerdrError(f"cannot export estate manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RappHerdrError(f"estate manifest must contain an object: {path}")
    candidate = _write_candidate(path.parent, payload)
    try:
        load_estate(candidate)
    finally:
        _unlink_quietly(candidate)
    return value


def export_estate_backup(manifest: str | Path) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    estate = _read_manifest(manifest_path)
    canonical = _canonical_manifest(estate)
    envelope = {
        "schema": BACKUP_SCHEMA,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "estate": estate,
    }
    serialize_backup_envelope(envelope)
    return envelope


def _estate_from_backup(value: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict):
        raise RappHerdrError("estate backup must contain a JSON object")
    schema = value.get("schema")
    if schema == ESTATE_SCHEMA:
        return value, ESTATE_SCHEMA
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


def _set_private_mode(path: Path) -> None:
    desired = stat.S_IREAD | stat.S_IWRITE if os.name == "nt" else 0o600
    path.chmod(desired)
    actual = stat.S_IMODE(path.stat().st_mode)
    valid = bool(actual & stat.S_IWRITE) if os.name == "nt" else actual == desired
    if not valid:
        raise PermissionError(
            f"could not set private permissions on {path}: mode is {actual:o}"
        )


def _set_private_mode_durably(path: Path) -> None:
    _set_private_mode(path)
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


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
        _set_private_mode(temporary_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _windows_move_file(source: Path, destination: Path) -> None:
    try:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file = kernel32.MoveFileExW
    except (AttributeError, OSError) as exc:
        raise AtomicCommitUnavailableError(
            "Windows atomic move support is unavailable"
        ) from exc
    move_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    move_file.restype = wintypes.BOOL
    if not move_file(str(source), str(destination), 0x1 | 0x8):
        error = ctypes.get_last_error()
        if error == 120:
            raise AtomicCommitUnavailableError(
                "Windows atomic move support is unavailable"
            )
        raise ctypes.WinError(error)


def _durable_replace(source: Path, destination: Path) -> None:
    if os.name == "nt":
        _windows_move_file(source, destination)
        return
    os.replace(source, destination)
    _fsync_directory(destination.parent)


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


def _process_exists(process_id: int) -> bool | None:
    if process_id <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return None
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, process_id)
        if not handle:
            return None if kernel32.GetLastError() == 5 else False
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return None
            return exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    except (AttributeError, OSError):
        return None


def _process_start_identity(process_id: int) -> str | None:
    if process_id <= 0:
        return None
    if sys.platform.startswith("linux"):
        try:
            stat_line = Path(f"/proc/{process_id}/stat").read_text(
                encoding="utf-8"
            )
            fields = stat_line[stat_line.rindex(")") + 2 :].split()
            start_ticks = fields[19]
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="utf-8"
            ).strip()
            return f"linux:{boot_id}:{start_ticks}"
        except (OSError, UnicodeError, ValueError, IndexError):
            return None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ps", "-o", "lstart=", "-p", str(process_id)],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        started = result.stdout.strip()
        return f"darwin:{started}" if result.returncode == 0 and started else None
    if os.name == "nt":
        try:
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, process_id)
            if not handle:
                return None
            try:
                creation = wintypes.FILETIME()
                exit_time = wintypes.FILETIME()
                kernel = wintypes.FILETIME()
                user = wintypes.FILETIME()
                if not kernel32.GetProcessTimes(
                    handle,
                    ctypes.byref(creation),
                    ctypes.byref(exit_time),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    return None
                ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
                return f"windows:{ticks}"
            finally:
                kernel32.CloseHandle(handle)
        except (AttributeError, OSError):
            return None
    return None


class _ImportLock:
    def __init__(
        self,
        manifest: Path,
        *,
        timeout: float = IMPORT_LOCK_TIMEOUT_SECONDS,
        stale_after: float = IMPORT_LOCK_STALE_SECONDS,
    ):
        self.path = manifest.with_name(f".{manifest.name}.import.lock")
        self.owner_path = self.path / "owner.json"
        self.timeout = timeout
        self.stale_after = stale_after
        self.token = uuid.uuid4().hex
        self._stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._lock_identity: tuple[int, int] | None = None

    def _owner_state(self) -> tuple[str, dict[str, Any] | None]:
        try:
            value = json.loads(self.owner_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return "missing", None
        except OSError:
            return "uncertain", None
        except (UnicodeError, json.JSONDecodeError):
            return "malformed", None
        if not isinstance(value, dict):
            return "malformed", None
        return "readable", value

    def _owner(self) -> dict[str, Any] | None:
        _state, owner = self._owner_state()
        return owner

    def _owns_current_lock(self) -> bool:
        owner = self._owner()
        return (
            owner is not None
            and owner.get("pid") == os.getpid()
            and owner.get("token") == self.token
        )

    def assert_owned(self) -> None:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise RappHerdrError(
                "estate import lock ownership was lost"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or self.path.is_symlink()
            or not self._owns_current_lock()
        ):
            raise RappHerdrError("estate import lock ownership was lost")

    def _heartbeat(self) -> None:
        interval = max(0.1, min(1.0, self.stale_after / 3))
        while not self._stop.wait(interval):
            if not self._owns_current_lock():
                return
            try:
                os.utime(self.owner_path, None)
            except OSError:
                return

    def _write_owner(self) -> None:
        value = {
            "pid": os.getpid(),
            "token": self.token,
            "created_at": time.time(),
            "process_identity": _process_start_identity(os.getpid()),
        }
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        temporary = self.path / f".owner-{self.token}.tmp"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _set_private_mode_durably(temporary)
            try:
                metadata = self.path.lstat()
            except OSError as exc:
                raise RappHerdrError(
                    "estate import lock ownership was lost while publishing "
                    "owner metadata"
                ) from exc
            if (
                self._lock_identity is None
                or (metadata.st_dev, metadata.st_ino) != self._lock_identity
            ):
                raise RappHerdrError(
                    "estate import lock ownership was lost while publishing "
                    "owner metadata"
                )
            _durable_replace(temporary, self.owner_path)
        finally:
            _unlink_quietly(temporary)

    @staticmethod
    def _valid_owner(
        owner: dict[str, Any] | None,
    ) -> tuple[int, str, str | None] | None:
        if owner is None:
            return None
        process_id = owner.get("pid")
        token = owner.get("token")
        process_identity = owner.get("process_identity")
        if (
            type(process_id) is not int
            or process_id <= 0
            or not isinstance(token, str)
            or not token
            or (
                process_identity is not None
                and not isinstance(process_identity, str)
            )
        ):
            return None
        return process_id, token, process_identity

    @staticmethod
    def _owner_process_is_live(
        owner: tuple[int, str, str | None],
    ) -> bool | None:
        process_id, _token, recorded_identity = owner
        exists = _process_exists(process_id)
        if exists is not True:
            return exists
        current_identity = _process_start_identity(process_id)
        if (
            recorded_identity is not None
            and current_identity is not None
            and not hmac.compare_digest(recorded_identity, current_identity)
        ):
            return False
        return True

    def _malformed_lock_is_stale(self) -> bool:
        try:
            owner_metadata = self.owner_path.lstat()
        except FileNotFoundError:
            owner_metadata = None
        except OSError:
            return False
        try:
            latest_activity = (
                owner_metadata.st_mtime
                if owner_metadata is not None
                else self.path.lstat().st_mtime
            )
            for child in self.path.iterdir():
                if child == self.owner_path:
                    continue
                latest_activity = max(latest_activity, child.lstat().st_mtime)
        except OSError:
            return False
        return time.time() - latest_activity >= self.stale_after

    def _quarantine(self) -> Path | None:
        quarantine = self.path.with_name(
            f"{self.path.name}.stale-{uuid.uuid4().hex}"
        )
        try:
            _durable_replace(self.path, quarantine)
        except FileNotFoundError:
            return None
        except OSError:
            if quarantine.is_dir() and not self.path.exists():
                return quarantine
            return None
        return quarantine

    def _restore_quarantined_live_lock(self, quarantine: Path) -> None:
        try:
            _durable_replace(quarantine, self.path)
        except OSError as exc:
            if self.path.is_dir() and not quarantine.exists():
                return
            raise RappHerdrError(
                "a live estate import lock changed while stale-lock "
                f"recovery was in progress; preserved at {quarantine}"
            ) from exc

    def _reap_if_stale(self) -> bool:
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if not stat.S_ISDIR(metadata.st_mode) or self.path.is_symlink():
            raise RappHerdrError(
                f"estate import lock is not a directory: {self.path}"
            )
        owner_state, owner = self._owner_state()
        if owner_state == "uncertain":
            return False
        valid_owner = self._valid_owner(owner)
        if valid_owner is not None:
            if self._owner_process_is_live(valid_owner) is not False:
                return False
        elif not self._malformed_lock_is_stale():
            return False
        owner_state, owner = self._owner_state()
        if owner_state == "uncertain":
            return False
        valid_owner = self._valid_owner(owner)
        if valid_owner is not None:
            if self._owner_process_is_live(valid_owner) is not False:
                return False
        elif not self._malformed_lock_is_stale():
            return False
        quarantine = self._quarantine()
        if quarantine is None:
            return not self.path.exists()
        quarantined_owner_path = quarantine / self.owner_path.name
        quarantined_owner_uncertain = False
        try:
            quarantined_owner = json.loads(
                quarantined_owner_path.read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            quarantined_owner = None
        except OSError:
            quarantined_owner = None
            quarantined_owner_uncertain = True
        except (UnicodeError, json.JSONDecodeError):
            quarantined_owner = None
        if not isinstance(quarantined_owner, dict):
            quarantined_owner = None
        quarantined_identity = self._valid_owner(quarantined_owner)
        if quarantined_owner_uncertain or (
            quarantined_identity is not None
        and self._owner_process_is_live(quarantined_identity) is not False
        ):
            self._restore_quarantined_live_lock(quarantine)
            return False
        shutil.rmtree(quarantine, ignore_errors=True)
        return True

    def acquire(self) -> None:
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self.path.mkdir(mode=0o700)
            except FileExistsError:
                if self._reap_if_stale():
                    continue
                if time.monotonic() >= deadline:
                    raise RappHerdrError(
                        "timed out waiting for another estate import to finish"
                    )
                time.sleep(
                    min(
                        self.timeout,
                        IMPORT_LOCK_POLL_SECONDS,
                        max(0.0, deadline - time.monotonic()),
                    )
                )
                continue
            except OSError as exc:
                raise RappHerdrError(
                    f"cannot acquire estate import lock {self.path}: {exc}"
                ) from exc
            metadata = self.path.lstat()
            self._lock_identity = (metadata.st_dev, metadata.st_ino)
            try:
                self._write_owner()
            except BaseException:
                if self._owns_current_lock():
                    self.owner_path.unlink(missing_ok=True)
                    try:
                        self.path.rmdir()
                    except OSError:
                        pass
                raise
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat,
                name="rapp-herdr-import-lock",
                daemon=True,
            )
            self._heartbeat_thread.start()
            return

    def release(self) -> None:
        self._stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=1.5)
        try:
            if not self._owns_current_lock():
                return
            self.owner_path.unlink(missing_ok=True)
            self.path.rmdir()
        except OSError:
            return

    def __enter__(self) -> _ImportLock:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


def _unlink_quietly(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def _path_matches_payload(path: Path, payload: bytes) -> bool:
    try:
        metadata = path.stat()
        if metadata.st_size != len(payload):
            return False
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(128 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return False
    return hmac.compare_digest(digest.digest(), hashlib.sha256(payload).digest())


def _native_atomic_exchange(source: Path, destination: Path) -> None:
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renamex_np = libc.renamex_np
        except AttributeError as exc:
            raise AtomicCommitUnavailableError(
                "macOS atomic exchange support is unavailable"
            ) from exc
        renamex_np.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(
            os.fsencode(source),
            os.fsencode(destination),
            0x00000002,
        )
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError as exc:
            raise AtomicCommitUnavailableError(
                "Linux renameat2 atomic exchange support is unavailable"
            ) from exc
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            0x00000002,
        )
    else:
        raise AtomicCommitUnavailableError(
            f"atomic file exchange is unsupported on {sys.platform}"
        )
    if result:
        error = ctypes.get_errno()
        unavailable = {
            errno.EINVAL,
            errno.ENOSYS,
            errno.ENOTSUP,
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        }
        if error in unavailable:
            raise AtomicCommitUnavailableError(
                f"atomic file exchange is unsupported by {source.parent}"
            )
        raise OSError(error, os.strerror(error), str(source), str(destination))
    _fsync_directory(destination.parent)


def _windows_replace_file(
    replaced: Path,
    replacement: Path,
    backup: Path,
) -> None:
    try:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        replace_file = kernel32.ReplaceFileW
    except (AttributeError, OSError) as exc:
        raise AtomicCommitUnavailableError(
            "Windows ReplaceFile support is unavailable"
        ) from exc
    replace_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    replace_file.restype = wintypes.BOOL
    if not replace_file(
        str(replaced),
        str(replacement),
        str(backup),
        0,
        None,
        None,
    ):
        error = ctypes.get_last_error()
        if error == 120:
            raise AtomicCommitUnavailableError(
                "Windows ReplaceFile support is unavailable"
            )
        raise ctypes.WinError(error)


def _platform_replace_with_backup(
    manifest: Path,
    candidate: Path,
    rollback: Path,
) -> None:
    if os.name == "nt":
        _windows_replace_file(manifest, candidate, rollback)
        return
    _native_atomic_exchange(candidate, manifest)


def _platform_restore_predecessor(
    manifest: Path,
    predecessor: Path,
    displaced: Path,
) -> None:
    if os.name == "nt":
        _windows_replace_file(manifest, predecessor, displaced)
        return
    _native_atomic_exchange(predecessor, manifest)


def _restore_conflicting_predecessor(
    manifest: Path,
    predecessor_path: Path,
    displaced_path: Path,
    predecessor_payload: bytes,
) -> None:
    try:
        _platform_restore_predecessor(
            manifest,
            predecessor_path,
            displaced_path,
        )
    except OSError as exc:
        if _path_matches_payload(manifest, predecessor_payload):
            return
        raise RappHerdrError(
            "estate manifest changed at the atomic commit point and its "
            "predecessor could not be restored"
        ) from exc
    if not _path_matches_payload(manifest, predecessor_payload):
        raise RappHerdrError(
            "estate manifest changed at the atomic commit point and its "
            "predecessor could not be verified after restoration"
        )


def _commit_candidate(
    manifest: Path,
    candidate: Path,
    rollback: Path,
    expected_payload: bytes,
    intended_payload: bytes,
) -> str | None:
    predecessor_path = rollback if os.name == "nt" else candidate
    warning: str | None = None
    try:
        _platform_replace_with_backup(manifest, candidate, rollback)
    except AtomicCommitUnavailableError:
        raise
    except OSError as exc:
        if not _path_matches_payload(manifest, intended_payload):
            raise
        if not predecessor_path.is_file():
            raise RappHerdrError(
                "the filesystem reported an ambiguous estate commit and "
                "the exact predecessor is unavailable"
            ) from exc
        warning = (
            "estate manifest was committed despite a filesystem error "
            f"reported at the commit point: {exc}"
        )

    try:
        predecessor_payload = predecessor_path.read_bytes()
    except OSError as exc:
        raise RappHerdrError(
            "cannot verify the estate manifest predecessor captured at "
            "the atomic commit point"
        ) from exc
    if predecessor_payload != expected_payload:
        _restore_conflicting_predecessor(
            manifest,
            predecessor_path,
            candidate,
            predecessor_payload,
        )
        raise ManifestConflictError(
            "estate manifest changed at the atomic commit point; "
            "the concurrent update was restored"
        )

    try:
        _set_private_mode_durably(predecessor_path)
    except OSError:
        _restore_conflicting_predecessor(
            manifest,
            predecessor_path,
            candidate,
            predecessor_payload,
        )
        raise

    if os.name != "nt":
        try:
            _durable_replace(candidate, rollback)
        except OSError as exc:
            if not _path_matches_payload(rollback, predecessor_payload):
                if (
                    _path_matches_payload(candidate, predecessor_payload)
                    and _path_matches_payload(manifest, intended_payload)
                ):
                    _restore_conflicting_predecessor(
                        manifest,
                        candidate,
                        candidate,
                        predecessor_payload,
                    )
                raise
            suffix = (
                "the predecessor backup was finalized despite a filesystem "
                f"error: {exc}"
            )
            warning = f"{warning}; {suffix}" if warning else suffix
    if not _path_matches_payload(rollback, predecessor_payload):
        raise RappHerdrError(
            "the exact estate manifest predecessor could not be verified"
        )
    if not _path_matches_payload(manifest, intended_payload):
        raise ManifestConflictError(
            "estate manifest was superseded immediately after the atomic "
            "commit; restore did not remain authoritative"
        )
    return warning


def import_estate_backup(
    manifest: str | Path,
    value: Any,
    *,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    manifest_path = Path(manifest).expanduser().resolve()
    if expected_manifest_sha256 is not None and (
        len(expected_manifest_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_manifest_sha256
        )
    ):
        raise RappHerdrError(
            "expected estate manifest checksum must be 64 lowercase hex characters"
        )
    estate, source_schema = _estate_from_backup(value)
    payload = _bounded_pretty_json(
        estate,
        "serialized estate manifest",
    )
    candidate: Path | None = None
    try:
        candidate = _write_candidate(manifest_path.parent, payload)
        validated = load_estate(candidate)
        with _ImportLock(manifest_path) as import_lock:
            if not manifest_path.is_file():
                raise RappHerdrError(
                    f"cannot replace missing estate manifest: {manifest_path}"
                )
            current_payload = manifest_path.read_bytes()
            current_generation = hashlib.sha256(current_payload).hexdigest()
            if (
                expected_manifest_sha256 is not None
                and not hmac.compare_digest(
                    expected_manifest_sha256,
                    current_generation,
                )
            ):
                raise ManifestConflictError(
                    "estate manifest changed before the guarded import"
                )
            rollback = _rollback_path(manifest_path)
            result: dict[str, Any] = {
                "ok": True,
                "committed": True,
                "estate": validated.name,
                "source_schema": source_schema,
                "previous_manifest": str(rollback),
            }
            import_lock.assert_owned()
            warning = _commit_candidate(
                manifest_path,
                candidate,
                rollback,
                current_payload,
                payload,
            )
            if warning is not None:
                result["warning"] = warning
            candidate = None
            return result
    except RappHerdrError:
        raise
    except OSError as exc:
        raise RappHerdrError(
            f"cannot import estate backup into {manifest_path}: {exc}"
        ) from exc
    finally:
        if candidate is not None and _path_matches_payload(candidate, payload):
            _unlink_quietly(candidate)
