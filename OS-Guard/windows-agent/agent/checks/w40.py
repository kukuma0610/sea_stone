"""W-40 read-only CHECK implementation."""

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

CHECK_ID = "W-40"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        policy = api.audit_policy()
        required = {'AuditAccountManage': 2, 'AuditAccountLogon': 3, 'AuditPrivilegeUse': 3, 'AuditDSAccess': 2, 'AuditLogonEvents': 3, 'AuditPolicyChange': 3}
        passed = all((int(policy[name]) & value == value for name, value in required.items()))
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W40_AUDIT_POLICY', {'audit_policy': policy})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
