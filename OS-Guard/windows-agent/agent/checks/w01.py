"""W-01 read-only CHECK implementation."""

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

CHECK_ID = "W-01"


# `Administrator 계정 이름 변경 등 보안성 강화` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: 기본 이름 변경 또는 강화된 비밀번호. 취약: 기본 이름 미변경 또는 단순 비밀번호. 방법: 로컬 보안 정책 확인. 원문 p.177”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `accounts()`로 이 항목에 필요한 Windows 정보를 읽어 `accounts`에 저장한다.
        accounts = api.accounts()
        # 수집값에서 판정에 필요한 `admin` 값을 계산하거나 골라낸다.
        admin = next((a for a in accounts if a['user_id'] == 500), None)
        # `admin is None` 조건으로 값 부재 또는 지원되지 않는 값을 구분해 오판정을 막는다.
        if admin is None:
            # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
            return _result(item_id, 'UNABLE', 'ADMINISTRATOR_ACCOUNT_NOT_FOUND', {}, manual_review_required=True)
        # 수집값이 `admin['name'] != 'Administrator'` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if admin['name'] != 'Administrator':
            # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'PASS', 'KISA_W01_NAME_CHANGED', {'administrator_name_changed': True})
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'PASSWORD_STRENGTH_REQUIRES_MANUAL_REVIEW', {'administrator_name_changed': False}, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
