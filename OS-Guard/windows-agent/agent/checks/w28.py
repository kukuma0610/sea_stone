"""W-28 read-only CHECK implementation."""

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

CHECK_ID = "W-28"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        rdp = api.rdp_inventory()
        if not rdp['service_running']:
            return _result(item_id, 'PASS', 'KISA_W28_RDP_NOT_RUNNING', {'service_running': False})
        level = rdp['minimum_encryption_level']
        if level is None:
            return _result(item_id, 'UNABLE', 'RDP_ENCRYPTION_LEVEL_NOT_FOUND', {'service_running': True}, manual_review_required=True)
        return _result(item_id, 'PASS' if level >= 2 else 'FAIL', 'KISA_W28_RDP_ENCRYPTION', {'service_running': True, 'minimum_encryption_level': level})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
