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


# `예약된 작업에 의심스러운 명령이 등록되어 있는지 점검` 항목을 읽기 전용으로 점검한다. KISA 기준은 “예약 작업을 주기적으로 점검하고 불필요 작업을 제거하면 양호, 미점검 또는 미제거면 취약 (KISA 원문 p.232)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `scheduled_task_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `inventory`에 저장한다.
        inventory = api.scheduled_task_inventory()
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'SCHEDULED_TASK_NECESSITY_AND_REVIEW_CYCLE_REQUIRE_MANUAL_REVIEW', {'task_count': int(inventory['task_count']), 'non_microsoft_task_count': int(inventory['non_microsoft_task_count']), 'non_microsoft_tasks_masked': [_mask_identifier(name) for name in inventory.get('non_microsoft_task_identifiers', [])]}, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
