"""W-47 read-only CHECK implementation."""

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

CHECK_ID = "W-47"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.screen_saver_inventory()
        if inventory.get("effective_verified") is True:
            enabled = inventory.get("enabled")
            protected = inventory.get("password_protected")
            timeout = inventory.get("timeout_seconds")
            if enabled is False or protected is False or (timeout is not None and (timeout == 0 or timeout > 600)):
                return _result(item_id, "FAIL", "KISA_W47_CURRENT_USER_SCREEN_SAVER", inventory,
                               manual_review_required=True)
        errors = [
            value["error_reason"] for value in inventory.get("effective", {}).values()
            if value.get("error_reason")
        ]
        return _result(item_id, 'UNABLE', 'SCREEN_SAVER_IS_USER_SCOPED_REQUIRES_MANUAL_REVIEW', inventory,
                       manual_review_required=True,
                       error_reason="; ".join(errors) or "Current-user settings do not verify all applicable user sessions")
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
