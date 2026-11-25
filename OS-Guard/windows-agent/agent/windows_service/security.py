"""제품 전용 경로와 서비스 SID ACL. OS 보안정책/사용자 권한은 변경하지 않는다."""

import ctypes
from ctypes import wintypes as W
from pathlib import Path
import os
import re

from ..central.storage import reject_reparse


class LocalError(RuntimeError):
    pass


def sid_for_account(account):
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    lookup = adv.LookupAccountNameW
    lookup.argtypes = [W.LPCWSTR, W.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(W.DWORD), W.LPWSTR, ctypes.POINTER(W.DWORD), ctypes.POINTER(W.DWORD)]
    lookup.restype = W.BOOL
    size, domain_size, kind = W.DWORD(), W.DWORD(), W.DWORD()
    lookup(None, account, None, ctypes.byref(size), None, ctypes.byref(domain_size), ctypes.byref(kind))
    if not size.value: raise LocalError("ACCOUNT_SID_UNAVAILABLE")
    buffer = ctypes.create_string_buffer(size.value)
    domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
    if not lookup(None, account, buffer, ctypes.byref(size), domain, ctypes.byref(domain_size), ctypes.byref(kind)):
        raise LocalError("ACCOUNT_SID_UNAVAILABLE")
    return sid_string(buffer)


def sid_string(pointer):
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = adv.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(W.LPWSTR)]
    convert.restype = W.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    result = W.LPWSTR()
    if not convert(pointer, ctypes.byref(result)): raise LocalError("SID_CONVERSION_FAILED")
    try: return result.value
    finally: kernel.LocalFree(ctypes.cast(result, ctypes.c_void_p))


def token_user():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)]
    adv.OpenProcessToken.restype = W.BOOL
    adv.GetTokenInformation.argtypes = [W.HANDLE, W.DWORD, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD)]
    adv.GetTokenInformation.restype = W.BOOL
    handle, size = W.HANDLE(), W.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(handle)):
        raise LocalError("TOKEN_QUERY_FAILED")
    try:
        adv.GetTokenInformation(handle, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(handle, 1, buffer, size, ctypes.byref(size)):
            raise LocalError("TOKEN_QUERY_FAILED")
        return sid_string(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0])
    finally: kernel.CloseHandle(handle)


def is_member(sid):
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSidToSidW.argtypes = [W.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertStringSidToSidW.restype = W.BOOL
    adv.CheckTokenMembership.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.POINTER(W.BOOL)]
    adv.CheckTokenMembership.restype = W.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    pointer, result = ctypes.c_void_p(), W.BOOL()
    if not adv.ConvertStringSidToSidW(sid, ctypes.byref(pointer)):
        raise LocalError("SID_CONVERSION_FAILED")
    try:
        if not adv.CheckTokenMembership(None, pointer, ctypes.byref(result)):
            raise LocalError("TOKEN_MEMBERSHIP_FAILED")
        return bool(result.value)
    finally: kernel.LocalFree(pointer)


def privilege_observation():
    class Luid(ctypes.Structure):
        _fields_ = [("low", W.DWORD), ("high", W.LONG)]
    class LuidAttributes(ctypes.Structure):
        _fields_ = [("luid", Luid), ("attributes", W.DWORD)]
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)]
    adv.OpenProcessToken.restype = W.BOOL
    adv.GetTokenInformation.argtypes = [W.HANDLE, W.DWORD, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD)]
    adv.GetTokenInformation.restype = W.BOOL
    adv.LookupPrivilegeNameW.argtypes = [W.LPCWSTR, ctypes.POINTER(Luid), W.LPWSTR, ctypes.POINTER(W.DWORD)]
    adv.LookupPrivilegeNameW.restype = W.BOOL
    handle, size = W.HANDLE(), W.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(handle)):
        raise LocalError("TOKEN_QUERY_FAILED")
    result = {name: {"present": False, "enabled": False} for name in
              ("SeRestorePrivilege", "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege")}
    try:
        adv.GetTokenInformation(handle, 3, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(handle, 3, buffer, size, ctypes.byref(size)):
            raise LocalError("TOKEN_QUERY_FAILED")
        count = ctypes.cast(buffer, ctypes.POINTER(W.DWORD))[0]
        offset = ctypes.sizeof(W.DWORD)
        if offset + count * ctypes.sizeof(LuidAttributes) > size.value: raise LocalError("TOKEN_QUERY_FAILED")
        entries = ctypes.cast(ctypes.addressof(buffer) + offset, ctypes.POINTER(LuidAttributes))
        for index in range(count):
            length = W.DWORD(128)
            name = ctypes.create_unicode_buffer(128)
            if not adv.LookupPrivilegeNameW(None, ctypes.byref(entries[index].luid), name, ctypes.byref(length)):
                raise LocalError("TOKEN_QUERY_FAILED")
            if name.value in result:
                result[name.value] = {"present": True, "enabled": bool(entries[index].attributes & 2)}
        return result
    finally: kernel.CloseHandle(handle)


def product_acl(path, service_sid, *, writable):
    if os.name != "nt" or (service_sid is not None and not re.fullmatch(r"S-1-5-80-(\d+-){4}\d+", service_sid)):
        raise LocalError("SERVICE_SID_INVALID")
    path = Path(path).absolute()
    reject_reparse(path)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [W.LPCWSTR, W.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = W.BOOL
    adv.SetFileSecurityW.argtypes = [W.LPCWSTR, W.DWORD, ctypes.c_void_p]
    adv.SetFileSecurityW.restype = W.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    flags = "OICI" if path.is_dir() else ""
    rights = "FA" if writable else "GRGX"
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
    if service_sid is not None: sddl += f"(A;{flags};{rights};;;{service_sid})"
    if not convert(sddl, 1, ctypes.byref(descriptor), None): raise LocalError("PRODUCT_ACL_FAILED")
    try:
        if not adv.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise LocalError("PRODUCT_ACL_FAILED")
    finally: kernel.LocalFree(descriptor)


def candidate_account(candidate):
    from . import SERVICE_NAME
    choices = {"virtual": "NT SERVICE\\" + SERVICE_NAME, "local-service": "NT AUTHORITY\\LocalService"}
    if candidate not in choices: raise LocalError("EXPLICIT_LOW_PRIVILEGE_CANDIDATE_REQUIRED")
    return choices[candidate]


def known_roots():
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.SHGetFolderPathW.argtypes = [W.HWND, ctypes.c_int, W.HANDLE, W.DWORD, W.LPWSTR]
    shell.SHGetFolderPathW.restype = ctypes.c_long
    roots = []
    for folder in (0x26, 0x23):  # Program Files / Common AppData, 사용자 환경변수를 신뢰하지 않음
        buffer = ctypes.create_unicode_buffer(32768)
        if shell.SHGetFolderPathW(None, folder, None, 0, buffer) != 0:
            raise LocalError("PRODUCT_ROOT_UNAVAILABLE")
        roots.append(Path(buffer.value) / "OS Guard Development Agent")
    return tuple(roots)
