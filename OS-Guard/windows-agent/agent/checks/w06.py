"""W-06 read-only CHECK implementation."""

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

CHECK_ID = "W-06"


# `관리자 그룹에 최소한의 사용자 포함` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: 관리자 1명 이하 또는 불필요 관리자 없음. 취약: 불필요 관리자 존재. 원문 p.182~183”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `administrator_group_members()`로 이 항목에 필요한 Windows 정보를 읽어 `members`에 저장한다.
        members = api.administrator_group_members()
        # 수집값에서 판정에 필요한 `evidence` 값을 계산하거나 골라낸다.
        evidence = [_mask_account_name(member) for member in members]
        # 수집값이 `len(members) <= 1` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if len(members) <= 1:
            # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'PASS', 'KISA_W06_ADMIN_COUNT', {'member_count': len(members), 'members_masked': evidence})
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'UNNECESSARY_ADMIN_REQUIRES_MANUAL_REVIEW', {'member_count': len(members), 'members_masked': evidence}, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
