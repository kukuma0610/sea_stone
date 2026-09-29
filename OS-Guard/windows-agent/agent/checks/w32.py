"""W-32 read-only CHECK implementation."""

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

CHECK_ID = "W-32"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        dns = api.dns_inventory()
        if not dns['service_running']:
            return _result(item_id, 'PASS', 'KISA_W32_DNS_NOT_RUNNING', {'service_running': False, 'zone_count': 0})
        updates = [zone.get('dynamic_update') for zone in dns['zones']]
        if not updates or any((value not in {'None', 'Secure', 'NonsecureAndSecure'} for value in updates)):
            return _result(item_id, 'UNABLE', 'DNS_DYNAMIC_UPDATE_NOT_DETERMINED', {'service_running': True, 'zone_count': len(updates)}, manual_review_required=True)
        enabled_count = sum((value != 'None' for value in updates))
        return _result(item_id, 'FAIL' if enabled_count else 'PASS', 'KISA_W32_DYNAMIC_UPDATE', {'service_running': True, 'zone_count': len(updates), 'dynamic_update_zone_count': enabled_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
