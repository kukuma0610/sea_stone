"""W-01 read-only CHECK implementation."""

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

CHECK_ID = "W-01"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        accounts = api.accounts()
        admin = next((a for a in accounts if a['user_id'] == 500), None)
        if admin is None:
            return _result(item_id, 'UNABLE', 'ADMINISTRATOR_ACCOUNT_NOT_FOUND', {}, manual_review_required=True)
        if admin['name'] != 'Administrator':
            return _result(item_id, 'PASS', 'KISA_W01_NAME_CHANGED', {'administrator_name_changed': True})
        return _result(item_id, 'UNABLE', 'PASSWORD_STRENGTH_REQUIRES_MANUAL_REVIEW', {'administrator_name_changed': False}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
