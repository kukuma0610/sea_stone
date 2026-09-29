"""W-48 read-only CHECK implementation."""

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

CHECK_ID = "W-48"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        enabled = api.shutdown_without_logon()
        if enabled is None:
            return _result(item_id, 'UNABLE', 'SHUTDOWN_WITHOUT_LOGON_POLICY_NOT_FOUND', {}, manual_review_required=True)
        return _result(item_id, 'FAIL' if enabled else 'PASS', 'KISA_W48_SHUTDOWN_WITHOUT_LOGON', {'enabled': enabled})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
