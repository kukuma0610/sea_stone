"""W-20 read-only CHECK implementation."""

import re

from typing import Any

from .common import (
    CheckObservation,
    NativeWindowsReadOnlyApi,
    WindowsApiUnavailable,
    _mask_account_name,
    _mask_identifier,
    _result,
    _seconds_to_days,
    _seconds_to_minutes,
)

CHECK_ID = "W-20"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        bindings = api.netbios_bindings()
        if not bindings:
            return _result(item_id, 'UNABLE', 'IP_ENABLED_ADAPTER_NOT_FOUND', {}, manual_review_required=True)
        enabled_count = sum((binding['tcpip_netbios_options'] != 2 for binding in bindings))
        return _result(item_id, 'FAIL' if enabled_count else 'PASS', 'KISA_W20_NETBIOS_BINDING', {'adapter_count': len(bindings), 'not_disabled_count': enabled_count, 'bindings': bindings})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
