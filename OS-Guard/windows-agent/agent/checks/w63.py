"""W-63 read-only CHECK implementation."""

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

CHECK_ID = "W-63"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        policy = api.kerberos_clock_skew_policy()
        if not policy['domain_joined']:
            return _result(item_id, 'UNABLE', 'KERBEROS_POLICY_NOT_AVAILABLE_ON_NON_DOMAIN_MEMBER', {'domain_joined': False}, manual_review_required=True)
        skew = policy['maximum_clock_skew_minutes']
        if skew is None:
            return _result(item_id, 'UNABLE', 'KERBEROS_CLOCK_SKEW_POLICY_NOT_FOUND', policy, manual_review_required=True)
        return _result(item_id, 'PASS' if int(skew) <= 5 else 'FAIL', 'KISA_W63_CLOCK_SKEW', policy)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
