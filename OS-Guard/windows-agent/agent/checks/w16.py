"""W-16 read-only CHECK implementation."""

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

CHECK_ID = "W-16"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        normal_shares = [share for share in api.shares() if not bool(share['special'])]
        everyone_count = sum((bool(share['everyone_allowed']) for share in normal_shares))
        return _result(item_id, 'FAIL' if everyone_count else 'PASS', 'KISA_W16_SHARE_EVERYONE', {'normal_share_count': len(normal_shares), 'everyone_share_count': everyone_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
