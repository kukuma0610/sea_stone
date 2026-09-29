"""W-29 read-only CHECK implementation."""

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

CHECK_ID = "W-29"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        snmp = api.snmp_inventory()
        if not snmp['service_running']:
            return _result(item_id, 'PASS', 'KISA_W29_SNMP_NOT_RUNNING', {'service_running': False})
        status = 'PASS' if snmp['community_count'] > 0 else 'FAIL'
        return _result(item_id, status, 'KISA_W29_SNMP_COMMUNITY_CONFIGURED', {'service_running': True, 'community_count': snmp['community_count']})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
