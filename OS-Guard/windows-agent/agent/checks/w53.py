"""W-53 read-only CHECK implementation."""

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

CHECK_ID = "W-53"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        value = api.removable_media_eject_policy()
        if value is None:
            return _result(item_id, 'UNABLE', 'REMOVABLE_MEDIA_POLICY_NOT_FOUND', {}, manual_review_required=True)
        return _result(item_id, 'PASS' if value == 0 else 'FAIL', 'KISA_W53_REMOVABLE_MEDIA', {'policy_value': value})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
