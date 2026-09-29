"""W-43 read-only CHECK implementation."""

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

CHECK_ID = "W-43"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        directories = api.log_directory_inventory()
        if not directories or any((not bool(entry['present']) for entry in directories)):
            return _result(item_id, 'UNABLE', 'LOG_DIRECTORY_NOT_FOUND', {'directory_count': len(directories)}, manual_review_required=True)
        everyone_count = sum((bool(entry['everyone_access']) for entry in directories))
        return _result(item_id, 'FAIL' if everyone_count else 'PASS', 'KISA_W43_LOG_DIRECTORY_ACCESS', {'directory_count': len(directories), 'everyone_access_count': everyone_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
