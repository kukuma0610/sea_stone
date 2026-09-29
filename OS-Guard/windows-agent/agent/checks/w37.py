"""W-37 read-only CHECK implementation."""

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

CHECK_ID = "W-37"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.scheduled_task_inventory()
        return _result(item_id, 'UNABLE', 'SCHEDULED_TASK_NECESSITY_AND_REVIEW_CYCLE_REQUIRE_MANUAL_REVIEW', {'task_count': int(inventory['task_count']), 'non_microsoft_task_count': int(inventory['non_microsoft_task_count']), 'non_microsoft_tasks_masked': [_mask_identifier(name) for name in inventory.get('non_microsoft_task_identifiers', [])]}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
