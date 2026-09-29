"""W-05 read-only CHECK implementation."""

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

CHECK_ID = "W-05"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        enabled = api.reversible_password_encryption_enabled()
        if api.domain_joined():
            return _result(item_id, 'UNABLE', 'DOMAIN_EFFECTIVE_POLICY_NOT_VERIFIED', {'local_policy_enabled': enabled}, manual_review_required=True, error_reason='Effective domain password policy requires VM verification')
        return _result(item_id, 'FAIL' if enabled else 'PASS', 'KISA_W05_REVERSIBLE_ENCRYPTION', {'reversible_password_encryption_enabled': enabled})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
