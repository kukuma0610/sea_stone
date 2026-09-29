"""W-42 read-only CHECK implementation."""

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

CHECK_ID = "W-42"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        logs = api.event_log_inventory()
        undersized_count = sum((int(log['maximum_size_kb']) < 10240 for log in logs))
        evidence = {'log_count': len(logs), 'undersized_log_count': undersized_count, 'logs': [{'name': log['name'], 'maximum_size_kb': int(log['maximum_size_kb']), 'log_mode': log['log_mode']} for log in logs]}
        if undersized_count:
            return _result(item_id, 'FAIL', 'KISA_W42_LOG_SIZE', evidence)
        return _result(item_id, 'UNABLE', 'EVENT_RETENTION_DAYS_NOT_AVAILABLE_ON_SERVER_2022', evidence, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
