"""W-59 read-only CHECK implementation."""

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

CHECK_ID = "W-59"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        level = api.lan_manager_authentication_level()
        if level is None or level not in range(0, 6):
            return _result(item_id, 'UNABLE', 'LAN_MANAGER_LEVEL_NOT_DETERMINED', {'authentication_level': level}, manual_review_required=True)
        return _result(item_id, 'PASS' if level >= 3 else 'FAIL', 'KISA_W59_LAN_MANAGER_LEVEL', {'authentication_level': level})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
