"""CurrentUser DPAPI + 보호 DACL + 원자적 파일 저장. 평문 fallback 없음."""

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
from threading import RLock


class StorageError(RuntimeError):
    pass


def reject_reparse(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        try:
            stat = part.lstat()
        except FileNotFoundError:
            continue
        if part.is_symlink() or getattr(stat, "st_file_attributes", 0) & 0x400:
            raise StorageError("state path contains a reparse point")


def restrict_acl(path):
    if os.name != "nt":
        raise StorageError("Windows protected storage is required")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    set_security = advapi.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    inheritance = "OICI" if Path(path).is_dir() else ""
    sddl = f"D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;OW)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise StorageError("state DACL conversion failed")
    try:
        if not set_security(str(path), 0x80000004, descriptor):
            raise StorageError("state DACL could not be protected")
    finally:
        kernel.LocalFree(descriptor)


class DPAPI:
    class Blob(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("data", ctypes.c_void_p)]

    def _transform(self, raw, decrypt):
        if os.name != "nt":
            raise StorageError("DPAPI requires Windows; no plaintext fallback")
        crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
        fn.argtypes = [ctypes.POINTER(self.Blob), ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(self.Blob)]
        fn.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        buffer = ctypes.create_string_buffer(raw)
        incoming = self.Blob(len(raw), ctypes.cast(buffer, ctypes.c_void_p))
        outgoing = self.Blob()
        # UI_FORBIDDEN만 설정. LOCAL_MACHINE은 사용하지 않는다.
        if not fn(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing)):
            raise StorageError("DPAPI operation failed for the current account")
        try:
            return ctypes.string_at(outgoing.data, outgoing.length)
        finally:
            kernel.LocalFree(outgoing.data)

    def protect(self, raw): return self._transform(raw, False)
    def unprotect(self, raw): return self._transform(raw, True)


class ProtectedState:
    def __init__(self, directory, *, protector=None, acl=restrict_acl):
        self.directory = Path(directory).absolute()
        reject_reparse(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.acl = acl
        self.acl(self.directory)
        self.protector = protector or DPAPI()
        self._process_lock = None
        if protector is None:
            import msvcrt
            lock_path = self.directory / "central.lock"
            reject_reparse(lock_path)
            handle = open(lock_path, "a+b")
            try:
                self.acl(lock_path)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except Exception:
                handle.close()
                raise StorageError("another runtime owns the protected state") from None
            self._process_lock = handle
        self.path = self.directory / "central-state.dpapi"
        self.lock = RLock()
        reject_reparse(self.path)
        if self.path.exists():
            self.acl(self.path)
            try:
                self.data = json.loads(self.protector.unprotect(self.path.read_bytes()))
            except Exception:
                raise StorageError("protected state cannot be restored") from None
        else:
            self.data = {"credential": None, "rotation": None, "outbox": {}, "active": None}

    def save(self):
        with self.lock:
            reject_reparse(self.path)
            raw = json.dumps(self.data, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
            protected = self.protector.protect(raw)
            fd, name = tempfile.mkstemp(prefix="central-", suffix=".dpapi.tmp", dir=self.directory)
            try:
                os.close(fd)
                self.acl(Path(name))
                with open(name, "wb") as stream:
                    stream.write(protected)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(name, self.path)
            finally:
                if Path(name).exists():
                    Path(name).unlink()

    def delete_credentials(self):
        with self.lock:
            self.data["credential"] = self.data["rotation"] = None
            self.save()

    def close(self):
        if self._process_lock is not None:
            self._process_lock.close()
            self._process_lock = None
