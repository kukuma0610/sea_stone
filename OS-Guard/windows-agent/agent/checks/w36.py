"""W-36 read-only CHECK implementation."""

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

CHECK_ID = "W-36"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        timeout = api.remote_idle_timeout_minutes()
        passed = timeout is not None and 0 < timeout <= 30
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W36_REMOTE_IDLE_TIMEOUT', {'idle_timeout_minutes': timeout})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
