from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .model import Neighborhood, RappHerdrError

RECEIPT_SCHEMA = "rapp-herdr-receipt/1.0"


class ReceiptStore:
    def __init__(self, root: str | Path | None = None):
        configured = root or os.environ.get("RAPP_HERDR_HOME")
        self.root = (
            Path(configured).expanduser()
            if configured
            else Path.home() / ".config" / "rapp-herdr"
        )

    def path_for(self, neighborhood: Neighborhood, socket_path: str) -> Path:
        material = f"{socket_path}\0{neighborhood.local_key}".encode()
        digest = hashlib.sha256(material).hexdigest()[:32]
        return self.root / "neighborhoods" / f"{digest}.json"

    def load(
        self,
        path: Path,
        *,
        schema: str = RECEIPT_SCHEMA,
    ) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RappHerdrError(f"invalid rapp-herdr receipt {path}: {exc}") from exc
        if not isinstance(value, dict) or value.get("schema") != schema:
            raise RappHerdrError(f"unsupported rapp-herdr receipt: {path}")
        return value

    def write(
        self,
        path: Path,
        receipt: dict[str, Any],
        *,
        schema: str = RECEIPT_SCHEMA,
    ) -> None:
        if receipt.get("schema") != schema:
            raise RappHerdrError("refusing to write a receipt with an unknown schema")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent, text=True
        )
        temporary = Path(temporary_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def delete(path: Path) -> None:
        path.unlink(missing_ok=True)

    def delete_if_token(self, path: Path, operation_token: str) -> bool:
        value = self.load(path)
        if value is None or value.get("operation_token") != operation_token:
            return False
        self.delete(path)
        return True

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            process_query_limited_information = 0x1000
            still_active = 259
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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

            handle = kernel32.OpenProcess(
                process_query_limited_information,
                False,
                pid,
            )
            if not handle:
                error = ctypes.get_last_error()
                if error == 87:  # ERROR_INVALID_PARAMETER: PID does not exist.
                    return False
                return True
            try:
                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return True
                return exit_code.value == still_active
            finally:
                kernel32.CloseHandle(handle)
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    @contextmanager
    def operation_lock(
        self,
        receipt_path: Path,
        *,
        wait_timeout: float = 0.0,
    ) -> Iterator[str]:
        lock_path = receipt_path.with_suffix(receipt_path.suffix + ".lock")
        owner_path = lock_path / "owner.json"
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(lock_path.parent, 0o700)
        token = uuid.uuid4().hex
        owner = {
            "token": token,
            "pid": os.getpid(),
            "host": platform.node(),
        }
        deadline = time.monotonic() + max(0.0, wait_timeout)

        while True:
            try:
                lock_path.mkdir(mode=0o700)
                try:
                    owner_path.write_text(
                        json.dumps(owner, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    os.chmod(owner_path, 0o600)
                except BaseException:
                    owner_path.unlink(missing_ok=True)
                    lock_path.rmdir()
                    raise
                break
            except FileExistsError:
                try:
                    current = json.loads(owner_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    if time.monotonic() < deadline:
                        time.sleep(0.05)
                        continue
                    raise RappHerdrError(
                        f"neighborhood operation lock is incomplete: {lock_path}"
                    ) from exc
                current_pid = current.get("pid")
                current_host = current.get("host")
                if (
                    current_host == platform.node()
                    and isinstance(current_pid, int)
                    and not self._pid_alive(current_pid)
                ):
                    owner_path.unlink(missing_ok=True)
                    try:
                        lock_path.rmdir()
                    except OSError as exc:
                        raise RappHerdrError(
                            f"cannot remove stale neighborhood lock: {lock_path}"
                        ) from exc
                    continue
                if time.monotonic() < deadline:
                    time.sleep(0.1)
                    continue
                raise RappHerdrError(
                    f"another neighborhood operation owns {lock_path} "
                    f"(host={current_host!r}, pid={current_pid!r})"
                )

        try:
            yield token
        finally:
            try:
                current = json.loads(owner_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                current = {}
            if current.get("token") != token:
                raise RappHerdrError(
                    f"neighborhood lock ownership changed unexpectedly: {lock_path}"
                )
            owner_path.unlink(missing_ok=True)
            try:
                lock_path.rmdir()
            except OSError as exc:
                raise RappHerdrError(
                    f"cannot release neighborhood lock: {lock_path}"
                ) from exc
