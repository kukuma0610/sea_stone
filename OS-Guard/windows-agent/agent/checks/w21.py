"""W-21 read-only CHECK implementation."""

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

CHECK_ID = "W-21"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        ftp = api.ftp_inventory()
        sites = ftp['sites']
        if not ftp['service_running']:
            return _result(item_id, 'PASS', 'KISA_W21_FTP_NOT_RUNNING', {'service_running': False, 'site_count': len(sites)})
        if not sites:
            return _result(item_id, 'UNABLE', 'FTP_CONFIGURATION_NOT_FOUND', {'service_running': True}, manual_review_required=True)
        insecure_count = sum((site['ssl_control_policy'].lower() != 'sslrequire' or site['ssl_data_policy'].lower() != 'sslrequire' for site in sites))
        return _result(item_id, 'FAIL' if insecure_count else 'PASS', 'KISA_W21_SECURE_FTP', {'service_running': True, 'site_count': len(sites), 'insecure_site_count': insecure_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
