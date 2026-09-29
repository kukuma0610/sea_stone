"""W-25 read-only CHECK implementation."""

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

CHECK_ID = "W-25"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        dns = api.dns_inventory()
        if not dns['service_running']:
            return _result(item_id, 'PASS', 'KISA_W25_DNS_NOT_RUNNING', {'service_running': False, 'zone_count': 0})
        allowed = {'NoTransfer', 'TransferToZoneNameServer', 'TransferToSecureServers'}
        denied = {'TransferToAnyServer'}
        transfer_types = [zone['transfer_type'] for zone in dns['zones']]
        if any((value not in allowed | denied for value in transfer_types)):
            return _result(item_id, 'UNABLE', 'DNS_TRANSFER_TYPE_UNRECOGNIZED', {'service_running': True, 'zone_count': len(transfer_types)}, manual_review_required=True)
        insecure_count = sum((value in denied for value in transfer_types))
        return _result(item_id, 'FAIL' if insecure_count else 'PASS', 'KISA_W25_ZONE_TRANSFER', {'service_running': True, 'zone_count': len(transfer_types), 'insecure_zone_count': insecure_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
