"""W-39 read-only CHECK implementation."""

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

CHECK_ID = "W-39"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.antivirus_inventory()
        return _result(item_id, 'UNABLE', 'ANTIVIRUS_CURRENCY_OR_ISOLATED_NETWORK_PROCEDURE_REQUIRES_MANUAL_REVIEW', {'defender_status_available': bool(inventory['defender_status_available']), 'antivirus_enabled': bool(inventory['antivirus_enabled']), 'signature_last_updated': inventory['signature_last_updated']}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
