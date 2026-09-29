"""W-24 read-only CHECK implementation."""

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

CHECK_ID = "W-24"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        ftp = api.ftp_inventory()
        sites = ftp['sites']
        if not sites:
            return _result(item_id, 'UNABLE', 'FTP_SITE_NOT_CONFIGURED', {'site_count': 0}, manual_review_required=True)
        unrestricted_count = sum((bool(site['ip_allow_unlisted']) or int(site['ip_allow_count']) == 0 for site in sites))
        return _result(item_id, 'FAIL' if unrestricted_count else 'PASS', 'KISA_W24_FTP_IP_RESTRICTION', {'site_count': len(sites), 'unrestricted_site_count': unrestricted_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
