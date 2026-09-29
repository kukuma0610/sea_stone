"""W-60 read-only CHECK implementation."""

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

CHECK_ID = "W-60"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        policy = api.secure_channel_policy()
        if not policy['domain_joined']:
            return _result(item_id, 'NA', 'KISA_W60_NOT_DOMAIN_MEMBER', {'domain_joined': False})
        values = [policy['require_sign_or_seal'], policy['seal_secure_channel'], policy['sign_secure_channel']]
        if any((value is None for value in values)):
            return _result(item_id, 'UNABLE', 'SECURE_CHANNEL_POLICY_NOT_FOUND', policy, manual_review_required=True)
        return _result(item_id, 'PASS' if all((value == 1 for value in values)) else 'FAIL', 'KISA_W60_SECURE_CHANNEL', policy)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
