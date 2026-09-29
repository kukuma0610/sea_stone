"""W-54 read-only CHECK implementation."""

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

CHECK_ID = "W-54"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        values = api.dos_defense_registry()
        if any((value is None for value in values.values())):
            return _result(item_id, 'FAIL', 'KISA_W54_DOS_REGISTRY_NOT_CONFIGURED', values)
        passed = int(values['SynAttackProtect']) >= 1 and values['EnableDeadGWDetect'] == 0 and (values['KeepAliveTime'] == 300000) and (values['NoNameReleaseOnDemand'] == 1)
        if passed:
            return _result(item_id, 'PASS', 'KISA_W54_DOS_REGISTRY', values)
        return _result(item_id, 'UNABLE', 'DOS_REGISTRY_VALUES_OUTSIDE_DOCUMENTED_DECISION', values, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
