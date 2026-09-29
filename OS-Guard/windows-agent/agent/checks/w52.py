"""W-52 read-only CHECK implementation."""

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

CHECK_ID = "W-52"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        value = api.auto_admin_logon()
        if value not in {0, 1}:
            return _result(item_id, 'UNABLE', 'AUTO_ADMIN_LOGON_VALUE_UNRECOGNIZED', {'auto_admin_logon': value}, manual_review_required=True)
        return _result(item_id, 'FAIL' if value == 1 else 'PASS', 'KISA_W52_AUTO_ADMIN_LOGON', {'auto_admin_logon': value})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
