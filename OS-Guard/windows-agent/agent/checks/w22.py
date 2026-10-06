"""W-22 read-only CHECK implementation."""

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

CHECK_ID = "W-22"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        ftp = getattr(api, "ftp_check_inventory", api.ftp_inventory)()
        sites = ftp['sites']
        if not sites:
            return _result(item_id, 'UNABLE', 'FTP_SITE_NOT_CONFIGURED', {'site_count': 0}, manual_review_required=True,
                           error_reason="No FTP sites available for directory permission verification")
        exposed_count = sum((bool(site['everyone_acl']) or bool(site['broad_authorization']) for site in sites))
        return _result(item_id, 'FAIL' if exposed_count else 'PASS', 'KISA_W22_FTP_PERMISSIONS', {'site_count': len(sites), 'everyone_or_broad_site_count': exposed_count})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
