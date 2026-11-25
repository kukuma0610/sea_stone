"""네이티브 SCM 어댑터. 호출은 설치 EXE 또는 SCM service dispatcher에서만 한다."""

import ctypes
from ctypes import wintypes as W
import threading
import time

from . import SERVICE_NAME, SERVICE_TITLE
from .security import LocalError


class Status(ctypes.Structure):
    _fields_ = [(name, W.DWORD) for name in ("kind", "state", "accepted", "exit_code", "specific", "checkpoint", "wait_hint")]


class Action(ctypes.Structure):
    _fields_ = [("kind", W.DWORD), ("delay", W.DWORD)]


class FailureActions(ctypes.Structure):
    _fields_ = [("reset", W.DWORD), ("reboot", W.LPWSTR), ("command", W.LPWSTR),
                ("count", W.DWORD), ("actions", ctypes.POINTER(Action))]


class ServiceConfig(ctypes.Structure):
    _fields_ = [("kind", W.DWORD), ("start", W.DWORD), ("error", W.DWORD),
                ("binary", W.LPWSTR), ("group", W.LPWSTR), ("tag", W.DWORD),
                ("dependencies", W.LPWSTR), ("account", W.LPWSTR), ("display", W.LPWSTR)]


class NativeSCM:
    def __init__(self):
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        self._bind("OpenSCManagerW", [W.LPCWSTR, W.LPCWSTR, W.DWORD], W.HANDLE)
        self._bind("OpenServiceW", [W.HANDLE, W.LPCWSTR, W.DWORD], W.HANDLE)
        self._bind("CloseServiceHandle", [W.HANDLE], W.BOOL)
        self._bind("CreateServiceW", [W.HANDLE, W.LPCWSTR, W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD,
                                     W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(W.DWORD), W.LPCWSTR, W.LPCWSTR, W.LPCWSTR], W.HANDLE)
        self._bind("ChangeServiceConfig2W", [W.HANDLE, W.DWORD, ctypes.c_void_p], W.BOOL)
        self._bind("DeleteService", [W.HANDLE], W.BOOL)
        self._bind("StartServiceW", [W.HANDLE, W.DWORD, ctypes.c_void_p], W.BOOL)
        self._bind("ControlService", [W.HANDLE, W.DWORD, ctypes.POINTER(Status)], W.BOOL)
        self._bind("QueryServiceStatus", [W.HANDLE, ctypes.POINTER(Status)], W.BOOL)
        self._bind("QueryServiceConfigW", [W.HANDLE, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD)], W.BOOL)

    def _bind(self, name, args, result):
        function = getattr(self.api, name)
        function.argtypes, function.restype = args, result

    def _open(self, access):
        manager = self.api.OpenSCManagerW(None, None, 1)
        if not manager: raise LocalError("SCM_ACCESS_DENIED")
        handle = self.api.OpenServiceW(manager, SERVICE_NAME, access)
        error = ctypes.get_last_error()
        self.api.CloseServiceHandle(manager)
        if not handle:
            if error == 1060: return None
            raise LocalError("SCM_SERVICE_ACCESS_DENIED")
        return handle

    def query(self):
        handle = self._open(1 | 4)
        if handle is None: return None
        try:
            size, status = W.DWORD(), Status()
            self.api.QueryServiceConfigW(handle, None, 0, ctypes.byref(size))
            if not size.value: raise LocalError("SCM_QUERY_FAILED")
            buffer = ctypes.create_string_buffer(size.value)
            if not self.api.QueryServiceConfigW(handle, buffer, size, ctypes.byref(size)) or not self.api.QueryServiceStatus(handle, ctypes.byref(status)):
                raise LocalError("SCM_QUERY_FAILED")
            config = ctypes.cast(buffer, ctypes.POINTER(ServiceConfig)).contents
            return {"binary": config.binary, "account": config.account, "state": status.state, "start": config.start}
        finally: self.api.CloseServiceHandle(handle)

    def create(self, binary, account):
        manager = self.api.OpenSCManagerW(None, None, 1 | 2)
        if not manager: raise LocalError("SCM_CREATE_DENIED")
        handle = None
        try:
            # AUTO_START=2, OWN_PROCESS=0x10. 비밀번호/임의 인수는 받지 않는다.
            handle = self.api.CreateServiceW(manager, SERVICE_NAME, SERVICE_TITLE, 0xF01FF, 0x10, 2, 1,
                                             binary, None, None, None, account, None)
            if not handle: raise LocalError("SCM_CREATE_FAILED")
            sid_type = W.DWORD(1)
            if not self.api.ChangeServiceConfig2W(handle, 5, ctypes.byref(sid_type)):
                raise LocalError("SCM_SID_CONFIGURATION_FAILED")
            actions = (Action * 3)(Action(1, 30000), Action(1, 120000), Action(0, 0))
            recovery = FailureActions(86400, None, None, 3, actions)
            if not self.api.ChangeServiceConfig2W(handle, 2, ctypes.byref(recovery)):
                raise LocalError("SCM_RECOVERY_CONFIGURATION_FAILED")
            noncrash_failures = W.DWORD(1)
            if not self.api.ChangeServiceConfig2W(handle, 4, ctypes.byref(noncrash_failures)):
                raise LocalError("SCM_RECOVERY_CONFIGURATION_FAILED")
            # 통신 서비스에 SeRestore/SeDebug/SeTcb/SeImpersonate 등을 추가하지 않는다.
            privileges = ctypes.create_unicode_buffer("SeChangeNotifyPrivilege\0\0")
            info = ctypes.c_void_p(ctypes.addressof(privileges))
            if not self.api.ChangeServiceConfig2W(handle, 6, ctypes.byref(info)):
                raise LocalError("SCM_PRIVILEGES_CONFIGURATION_FAILED")
        except Exception:
            if handle: self.api.DeleteService(handle)
            raise
        finally:
            if handle: self.api.CloseServiceHandle(handle)
            self.api.CloseServiceHandle(manager)

    def start(self):
        handle = self._open(0x10 | 4)
        if handle is None: raise LocalError("SERVICE_MISSING")
        try:
            if not self.api.StartServiceW(handle, 0, None) and ctypes.get_last_error() != 1056:
                raise LocalError("SERVICE_START_FAILED")
            self._wait(handle, 4)
        finally: self.api.CloseServiceHandle(handle)

    def stop(self):
        handle = self._open(0x20 | 4)
        if handle is None: return
        try:
            status = Status()
            if not self.api.ControlService(handle, 1, ctypes.byref(status)) and ctypes.get_last_error() != 1062:
                raise LocalError("SERVICE_STOP_FAILED")
            self._wait(handle, 1)
        finally: self.api.CloseServiceHandle(handle)

    def _wait(self, handle, expected):
        deadline = time.monotonic() + 150  # inventory의 기존 bounded 읽기 완료를 기다린다.
        while time.monotonic() < deadline:
            status = Status()
            if not self.api.QueryServiceStatus(handle, ctypes.byref(status)): raise LocalError("SCM_QUERY_FAILED")
            if status.state == expected: return
            time.sleep(0.2)
        raise LocalError("SCM_STATE_TIMEOUT")

    def delete(self):
        handle = self._open(0x10000)
        if handle is None: return
        try:
            if not self.api.DeleteService(handle): raise LocalError("SERVICE_DELETE_FAILED")
        finally: self.api.CloseServiceHandle(handle)


def dispatch(worker):
    """SCM stop는 stop event만 설정. worker가 보호 state를 닫은 뒤 STOPPED 보고."""
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    handler_type = ctypes.WINFUNCTYPE(W.DWORD, W.DWORD, W.DWORD, ctypes.c_void_p, ctypes.c_void_p)
    main_type = ctypes.WINFUNCTYPE(None, W.DWORD, ctypes.POINTER(W.LPWSTR))
    class Entry(ctypes.Structure):
        _fields_ = [("name", W.LPWSTR), ("main", main_type)]
    api.RegisterServiceCtrlHandlerExW.argtypes = [W.LPCWSTR, handler_type, ctypes.c_void_p]
    api.RegisterServiceCtrlHandlerExW.restype = W.HANDLE
    api.SetServiceStatus.argtypes = [W.HANDLE, ctypes.POINTER(Status)]
    api.SetServiceStatus.restype = W.BOOL
    api.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(Entry)]
    api.StartServiceCtrlDispatcherW.restype = W.BOOL
    stop, lock = threading.Event(), threading.RLock()
    handle, current, checkpoint = None, 2, 0

    def report(state, error=0):
        nonlocal current, checkpoint
        with lock:
            current = state
            pending = state in {2, 3}
            checkpoint = checkpoint + 1 if pending else 0
            status = Status(0x10, state, 5 if state == 4 else 0, error, 1 if error == 1066 else 0, checkpoint, 30000 if pending else 0)
            if not api.SetServiceStatus(handle, ctypes.byref(status)):
                stop.set()

    @handler_type
    def control(code, event, data, context):
        if code in {1, 5}:
            stop.set()
            report(3)
        elif code == 4: report(current)
        return 0

    @main_type
    def service_main(count, args):
        nonlocal handle
        handle = api.RegisterServiceCtrlHandlerExW(SERVICE_NAME, control, None)
        if not handle: return
        report(2)
        try:
            if not stop.is_set(): report(4)
            done, failures = threading.Event(), []
            def execute():
                try: worker(stop)
                except BaseException: failures.append(True)
                finally: done.set()
            thread = threading.Thread(target=execute)
            thread.start()
            while not done.wait(2):
                if stop.is_set(): report(3)
            thread.join()
            report(1, 1066 if failures else 0)
        except BaseException:
            # 예외 원문/credential은 SCM/console에 보내지 않는다.
            report(1, 1066)

    entries = (Entry * 2)(Entry(SERVICE_NAME, service_main), Entry(None, main_type()))
    if not api.StartServiceCtrlDispatcherW(entries): raise LocalError("SCM_DISPATCH_FAILED")
