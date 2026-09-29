"""W-34 read-only CHECK implementation."""

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

CHECK_ID = "W-34"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        os_info = api.windows_os_info()
        if 'Windows Server 2022' in os_info['caption']:
            return _result(item_id, 'NA', 'KISA_W34_SERVER_2022_NOT_APPLICABLE', {'caption': os_info['caption']})
        return _result(item_id, 'UNABLE', 'TELNET_AUTHENTICATION_REQUIRES_APPLICABLE_OS_REVIEW', {'caption': os_info['caption']}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
