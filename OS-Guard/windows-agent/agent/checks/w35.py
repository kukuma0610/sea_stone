"""W-35 read-only CHECK implementation."""

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

CHECK_ID = "W-35"


# `불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거` 항목을 읽기 전용으로 점검한다. KISA 기준은 “시스템 DSN을 현재 사용하면 양호, 사용하지 않으면 취약 (KISA 원문 p.229)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `odbc_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `inventory`에 저장한다.
        inventory = api.odbc_inventory()
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'ODBC_USAGE_REQUIRES_MANUAL_REVIEW', {'system_dsn_count': int(inventory['system_dsn_count']), 'driver_count': int(inventory['driver_count']), 'system_dsns_masked': [_mask_identifier(name) for name in inventory.get('system_dsn_names', [])], 'drivers_masked': [_mask_identifier(name) for name in inventory.get('driver_names', [])]}, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
