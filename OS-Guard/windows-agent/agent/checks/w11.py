"""W-11 read-only CHECK implementation."""

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

CHECK_ID = "W-11"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        principals = api.local_logon_principals()
        unexpected = [principal for principal in principals if principal != 'BUILTIN_ADMINISTRATORS' and (not principal.split('\\')[-1].startswith('IUSR_'))]
        evidence = [_mask_account_name(principal) for principal in principals]
        return _result(item_id, 'FAIL' if unexpected else 'PASS', 'KISA_W11_LOCAL_LOGON', {'principal_count': len(principals), 'principals_masked': evidence})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
