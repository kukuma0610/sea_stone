"""W-02 read-only CHECK implementation."""

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

CHECK_ID = "W-02"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        accounts = api.accounts()
        guest = next((a for a in accounts if a['user_id'] == 501), None)
        if guest is None:
            return _result(item_id, 'UNABLE', 'GUEST_ACCOUNT_NOT_FOUND', {}, manual_review_required=True)
        return _result(item_id, 'PASS' if guest['disabled'] else 'FAIL', 'KISA_W02_GUEST_STATE', {'guest_disabled': guest['disabled']})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
