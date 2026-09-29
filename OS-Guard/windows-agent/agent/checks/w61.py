"""W-61 read-only CHECK implementation."""

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

CHECK_ID = "W-61"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.fixed_volume_inventory()
        if inventory['fat_count']:
            return _result(item_id, 'FAIL', 'KISA_W61_FAT_FILESYSTEM', inventory)
        if inventory['volume_count'] == 0 or inventory['other_filesystem_count']:
            return _result(item_id, 'UNABLE', 'FILESYSTEM_OUTSIDE_KISA_DECISION', inventory, manual_review_required=True)
        return _result(item_id, 'PASS', 'KISA_W61_NTFS_FILESYSTEM', inventory)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
