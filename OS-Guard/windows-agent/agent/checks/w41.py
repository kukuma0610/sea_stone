"""W-41 read-only CHECK implementation."""

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

CHECK_ID = "W-41"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        inventory = api.time_sync_inventory()
        sync_type = inventory['sync_type'].casefold()
        configured = bool(inventory['service_running']) and sync_type not in {'', 'nosync'} and (sync_type == 'nt5ds' or bool(inventory['ntp_server_configured']))
        return _result(item_id, 'PASS' if configured else 'FAIL', 'KISA_W41_TIME_SYNC', inventory)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
