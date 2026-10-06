"""W-47 read-only CHECK implementation."""

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

CHECK_ID = "W-47"


# `화면보호기 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “화면 보호기 사용·10분 이하·해제 암호 사용 시 양호, 하나라도 미충족 시 취약 (KISA 원문 p.244~245)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `screen_saver_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `inventory`에 저장한다.
        inventory = api.screen_saver_inventory()
        # 수집값이 `inventory.get("effective_verified") is True` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if inventory.get("effective_verified") is True:
            enabled = inventory.get("enabled")
            protected = inventory.get("password_protected")
            timeout = inventory.get("timeout_seconds")
            # 수집값이 `enabled is False or protected is False or (timeout is not None and (timeout == 0 or timeout > 600))` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
            if enabled is False or protected is False or (timeout is not None and (timeout == 0 or timeout > 600)):
                return _result(item_id, "FAIL", "KISA_W47_CURRENT_USER_SCREEN_SAVER", inventory,
                               manual_review_required=True)
        # 수집값에서 판정에 필요한 `errors` 값을 계산하거나 골라낸다.
        errors = [
            value["error_reason"] for value in inventory.get("effective", {}).values()
            if value.get("error_reason")
        ]
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'SCREEN_SAVER_IS_USER_SCOPED_REQUIRES_MANUAL_REVIEW', inventory,
                       manual_review_required=True,
                       error_reason="; ".join(errors) or "Current-user settings do not verify all applicable user sessions")
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
