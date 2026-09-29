"""W-09 read-only CHECK implementation."""

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

CHECK_ID = "W-09"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        policy = api.password_policy()
        values = {'complexity_enabled': bool(policy['complexity_enabled']), 'minimum_length': int(policy['minimum_length']), 'maximum_age_days': _seconds_to_days(int(policy['maximum_age_seconds'])), 'minimum_age_days': _seconds_to_days(int(policy['minimum_age_seconds'])), 'history_length': int(policy['history_length'])}
        passed = values['complexity_enabled'] and values['minimum_length'] >= 8 and (0 < values['maximum_age_days'] <= 90) and (values['minimum_age_days'] >= 1) and (values['history_length'] >= 4)
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W09_PASSWORD_POLICY', values)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
