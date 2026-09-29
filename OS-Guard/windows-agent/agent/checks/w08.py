"""W-08 read-only CHECK implementation."""

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

CHECK_ID = "W-08"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        policy = api.lockout_policy()
        duration = _seconds_to_minutes(policy['duration_seconds'])
        reset = _seconds_to_minutes(policy['reset_seconds'])
        passed = duration >= 60 and reset >= 60
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W08_LOCKOUT_PERIODS', {'lockout_duration_minutes': duration, 'reset_lockout_count_minutes': reset})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
