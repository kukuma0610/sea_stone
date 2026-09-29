"""W-14 read-only CHECK implementation."""

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

CHECK_ID = "W-14"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        members = api.remote_desktop_group_members()
        evidence = [_mask_account_name(member) for member in members]
        if not members:
            return _result(item_id, 'FAIL', 'KISA_W14_NO_DEDICATED_REMOTE_ACCOUNT', {'member_count': 0, 'members_masked': []})
        return _result(item_id, 'UNABLE', 'REMOTE_ACCOUNT_AUTHORIZATION_REQUIRES_MANUAL_REVIEW', {'member_count': len(members), 'members_masked': evidence}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
