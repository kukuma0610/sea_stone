"""W-64 read-only CHECK implementation."""

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

CHECK_ID = "W-64"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        profiles = api.firewall_profile_inventory()
        if not profiles:
            return _result(item_id, 'UNABLE', 'FIREWALL_PROFILES_NOT_FOUND', {}, manual_review_required=True)
        disabled_count = sum((not bool(profile['enabled']) for profile in profiles))
        return _result(item_id, 'FAIL' if disabled_count else 'PASS', 'KISA_W64_FIREWALL', {'profile_count': len(profiles), 'disabled_profile_count': disabled_count, 'profiles': profiles})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
