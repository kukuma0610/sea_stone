"""승인 등록 전용 로컬 IPC. 주장된 SID 대신 읽은 메시지의 Windows 토큰을 조회한다."""

import ctypes as C
from ctypes import wintypes as W
import json
import time

from agent.windows_service.security import sid_string
from scripts.lab_hardening_policy import require


class Overlapped(C.Structure):
    _fields_ = [("Internal", C.c_size_t), ("InternalHigh", C.c_size_t),
                ("Offset", W.DWORD), ("OffsetHigh", W.DWORD), ("hEvent", W.HANDLE)]


class SecurityAttributes(C.Structure):
    _fields_ = [("nLength", W.DWORD), ("lpSecurityDescriptor", C.c_void_p), ("bInheritHandle", W.BOOL)]


class ApprovalPipe:
    def __init__(self, name, owner_sid):
        self.owner_sid = owner_sid
        self.cancelled = lambda: False
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self.a = C.WinDLL("advapi32", use_last_error=True)
        def bind(lib, name, args, result=W.BOOL):
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, result
        bind(self.k, "CreateNamedPipeW", [W.LPCWSTR,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.DWORD,C.POINTER(SecurityAttributes)], W.HANDLE)
        bind(self.k, "ConnectNamedPipe", [W.HANDLE,C.POINTER(Overlapped)])
        bind(self.k, "ReadFile", [W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.POINTER(Overlapped)])
        bind(self.k, "WriteFile", [W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.POINTER(Overlapped)])
        bind(self.k, "GetOverlappedResult", [W.HANDLE,C.POINTER(Overlapped),C.POINTER(W.DWORD),W.BOOL])
        bind(self.k, "CancelIoEx", [W.HANDLE,C.POINTER(Overlapped)])
        bind(self.k, "CreateEventW", [C.c_void_p,W.BOOL,W.BOOL,W.LPCWSTR], W.HANDLE)
        bind(self.k, "WaitForSingleObject", [W.HANDLE,W.DWORD], W.DWORD)
        bind(self.k, "CloseHandle", [W.HANDLE])
        bind(self.k, "LocalFree", [C.c_void_p], C.c_void_p)
        bind(self.k, "GetCurrentThread", [], W.HANDLE)
        bind(self.a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.c_void_p])
        bind(self.a, "ImpersonateNamedPipeClient", [W.HANDLE])
        bind(self.a, "RevertToSelf", [])
        bind(self.a, "OpenThreadToken", [W.HANDLE,W.DWORD,W.BOOL,C.POINTER(W.HANDLE)])
        bind(self.a, "GetTokenInformation", [W.HANDLE,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)])
        descriptor = C.c_void_p()
        sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner_sid})"
        require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(descriptor), None), "PIPE_DACL_FAILED")
        try:
            security = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
            # 최초 인스턴스·로컬 연결·1개 클라이언트만 허용한다.
            self.handle = self.k.CreateNamedPipeW("\\\\.\\pipe\\"+name, 3|0x40000000|0x80000,
                                                   4|2|8, 1, 8192, 8192, 0, C.byref(security))
            require(self.handle not in (None, C.c_void_p(-1).value), "PIPE_CREATE_FAILED")
        finally:
            self.k.LocalFree(descriptor)

    def io(self, operation, *, connected=False):
        event = self.k.CreateEventW(None, True, False, None)
        require(event, "PIPE_EVENT_FAILED")
        ov, count = Overlapped(), W.DWORD()
        ov.hEvent = event
        try:
            ok = operation(C.byref(ov))
            error = C.get_last_error()
            if not ok and connected and error == 535:  # ERROR_PIPE_CONNECTED
                return 0
            require(ok or error == 997, "PIPE_IO_FAILED")  # ERROR_IO_PENDING
            if not ok:
                deadline = time.monotonic()+300
                while True:
                    state = self.k.WaitForSingleObject(event, 200)
                    if state == 0:
                        break
                    if state != 258 or time.monotonic() >= deadline or self.cancelled():
                        break
                if state != 0:
                    reason = "OWNER_LOGON_OR_WINDOW_CLOSED" if self.cancelled() else "APPROVER_TIMEOUT"
                    self.k.CancelIoEx(self.handle, C.byref(ov))
                    self.k.GetOverlappedResult(self.handle, C.byref(ov), C.byref(count), True)
                    require(False, reason)
            require(self.k.GetOverlappedResult(self.handle, C.byref(ov), C.byref(count), False), "PIPE_IO_FAILED")
            return count.value
        finally:
            self.k.CloseHandle(event)

    def peer_sid(self):
        token = W.HANDLE()
        try:
            require(self.a.ImpersonateNamedPipeClient(self.handle), "PIPE_IMPERSONATION_FAILED")
            require(self.a.OpenThreadToken(self.k.GetCurrentThread(), 8, True, C.byref(token)), "PIPE_TOKEN_FAILED")
            size = W.DWORD()
            self.a.GetTokenInformation(token, 1, None, 0, C.byref(size))
            require(0 < size.value <= 65536, "PIPE_TOKEN_INVALID")
            buffer = C.create_string_buffer(size.value)
            require(self.a.GetTokenInformation(token, 1, buffer, size, C.byref(size)), "PIPE_TOKEN_FAILED")
            return sid_string(C.cast(buffer, C.POINTER(C.c_void_p))[0])
        finally:
            if token: self.k.CloseHandle(token)
            require(self.a.RevertToSelf(), "PIPE_REVERT_FAILED")

    def approve(self, request):
        self.io(lambda ov: self.k.ConnectNamedPipe(self.handle, ov), connected=True)
        raw = (json.dumps(request, ensure_ascii=True)+"\n").encode("utf-8")
        require(len(raw) < 8192, "PIPE_REQUEST_TOO_LARGE")
        buffer = C.create_string_buffer(raw)
        count = self.io(lambda ov: self.k.WriteFile(self.handle, buffer, len(raw), None, ov))
        require(count == len(raw), "PIPE_SHORT_WRITE")
        incoming = C.create_string_buffer(8192)
        count = self.io(lambda ov: self.k.ReadFile(self.handle, incoming, 8192, None, ov))
        require(0 < count < 8192, "PIPE_RESPONSE_INVALID")
        # 인증 정보는 메시지의 sid 필드가 아니라 마지막 메시지를 보낸 OS 토큰에서 얻는다.
        sid = self.peer_sid()
        require(sid == self.owner_sid, "OWNER_LOGON_SID_MISMATCH")
        message = json.loads(incoming.raw[:count].decode("utf-8-sig"))
        require(isinstance(message, dict) and set(message) == {"approval_id", "nonce", "accepted"}, "PIPE_RESPONSE_INVALID")
        require(message["approval_id"] == request["approval_id"] and message["nonce"] == request["nonce"]
                and message["accepted"] is True, "OWNER_RISK_NOT_ACCEPTED")
        acknowledgement = C.create_string_buffer(b'{"received":true}\n')
        self.io(lambda ov: self.k.WriteFile(self.handle, acknowledgement, len(acknowledgement.value), None, ov))
        return sid

    def close(self):
        self.k.CloseHandle(self.handle)
