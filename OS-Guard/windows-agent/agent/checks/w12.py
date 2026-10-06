"""W-12 read-only CHECK implementation."""

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

CHECK_ID = "W-12"


# `익명 SID/이름 변환 허용 해제` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: 사용 안 함. 취약: 사용. 원문 p.192”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `anonymous_sid_name_translation_enabled()`로 이 항목에 필요한 Windows 정보를 읽어 `enabled`에 저장한다.
        enabled = api.anonymous_sid_name_translation_enabled()
        # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
        return _result(item_id, 'FAIL' if enabled else 'PASS', 'KISA_W12_ANONYMOUS_SID', {'anonymous_sid_name_translation_enabled': enabled})
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
