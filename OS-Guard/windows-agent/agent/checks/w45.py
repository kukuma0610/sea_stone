"""W-45 read-only CHECK implementation."""

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

CHECK_ID = "W-45"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.antivirus_inventory()
        if inventory['defender_status_available']:
            return _result(item_id, 'PASS', 'KISA_W45_DEFENDER_INSTALLED', {'defender_status_available': True, 'antivirus_enabled': bool(inventory['antivirus_enabled'])})
        return _result(item_id, 'UNABLE', 'THIRD_PARTY_ANTIVIRUS_REQUIRES_MANUAL_REVIEW', {'defender_status_available': False}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
