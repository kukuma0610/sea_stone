"""W-06 read-only CHECK implementation."""

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

CHECK_ID = "W-06"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        members = api.administrator_group_members()
        evidence = [_mask_account_name(member) for member in members]
        if len(members) <= 1:
            return _result(item_id, 'PASS', 'KISA_W06_ADMIN_COUNT', {'member_count': len(members), 'members_masked': evidence})
        return _result(item_id, 'UNABLE', 'UNNECESSARY_ADMIN_REQUIRES_MANUAL_REVIEW', {'member_count': len(members), 'members_masked': evidence}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
