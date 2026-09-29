"""W-23 read-only CHECK implementation."""

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

CHECK_ID = "W-23"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        ftp = api.ftp_inventory()
        anonymous_count = sum((bool(site['anonymous_enabled']) for site in ftp['sites']))
        if anonymous_count:
            return _result(item_id, 'FAIL', 'KISA_W23_FTP_ANONYMOUS_ENABLED', {'ftp_site_count': len(ftp['sites']), 'anonymous_ftp_site_count': anonymous_count})
        normal_share_count = sum((not bool(share['special']) for share in api.shares()))
        auxiliary = api.auxiliary_share_services()
        if normal_share_count or auxiliary:
            return _result(item_id, 'FAIL', 'KISA_W23_SHARE_SERVICE_IN_USE', {'ftp_site_count': len(ftp['sites']), 'normal_smb_share_count': normal_share_count, 'auxiliary_share_service_count': len(auxiliary)})
        return _result(item_id, 'PASS', 'KISA_W23_ANONYMOUS_DISABLED', {'ftp_site_count': len(ftp['sites']), 'anonymous_ftp_site_count': 0})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
