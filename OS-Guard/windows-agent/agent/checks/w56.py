"""W-56 read-only CHECK implementation."""

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

CHECK_ID = "W-56"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        policy = api.smb_session_policy()
        if any((value is None for value in policy.values())):
            return _result(item_id, 'UNABLE', 'SMB_SESSION_POLICY_NOT_FOUND', policy, manual_review_required=True)
        passed = policy['enable_forced_logoff'] == 1 and int(policy['autodisconnect_minutes']) <= 15
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W56_SMB_SESSION', policy)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
