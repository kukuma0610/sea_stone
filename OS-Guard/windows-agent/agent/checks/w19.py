"""W-19 read-only CHECK implementation."""

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

CHECK_ID = "W-19"


def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        api = api or NativeWindowsReadOnlyApi()
        services = api.iis_services()
        running = [service for service in services if service['status'].lower() == 'running']
        if not running:
            return _result(item_id, 'PASS', 'KISA_W19_IIS_NOT_RUNNING', {'installed_service_count': len(services), 'running_service_count': 0})
        return _result(item_id, 'UNABLE', 'IIS_NECESSITY_REQUIRES_MANUAL_REVIEW', {'installed_service_count': len(services), 'running_service_count': len(running)}, manual_review_required=True)
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
