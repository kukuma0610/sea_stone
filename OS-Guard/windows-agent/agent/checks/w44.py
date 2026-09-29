"""W-44 read-only CHECK implementation."""

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

CHECK_ID = "W-44"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        running = api.remote_registry_running()
        return _result(item_id, 'FAIL' if running else 'PASS', 'KISA_W44_REMOTE_REGISTRY', {'service_running': running})
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
