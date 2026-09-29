"""W-35 read-only CHECK implementation."""

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

CHECK_ID = "W-35"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.odbc_inventory()
        return _result(item_id, 'UNABLE', 'ODBC_USAGE_REQUIRES_MANUAL_REVIEW', {'system_dsn_count': int(inventory['system_dsn_count']), 'driver_count': int(inventory['driver_count']), 'system_dsns_masked': [_mask_identifier(name) for name in inventory.get('system_dsn_names', [])], 'drivers_masked': [_mask_identifier(name) for name in inventory.get('driver_names', [])]}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
