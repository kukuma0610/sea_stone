"""Compatibility entry point and dispatcher for Windows CHECKs."""

from typing import Any

from .checks.common import (
    CheckObservation,
    KISA_SOURCES,
    NativeWindowsReadOnlyApi,
    WINDOWS_CHECKS,
    WindowsApiUnavailable,
    _parse_dont_display_last_username,
    _parse_registry_dword,
    _parse_reversible_password_encryption,
    _parse_security_policy_flag,
    _parse_security_policy_list,
)


def collect_check(item_id: str, api: Any | None = None) -> CheckObservation:
    """Dispatch a Windows check through its independent W-code module."""
    from .checks import CHECK_REGISTRY

    try:
        checker = CHECK_REGISTRY[item_id]
    except KeyError as exc:
        raise ValueError("unsupported Windows check item") from exc
    return checker(api)
