"""W-56 read-only CHECK implementation."""

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

CHECK_ID = "W-56"


# `SMB 세션 중단 관리 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “로그온 만료 시 연결 끊기 사용 및 SMB 유휴 시간 15분 이하이면 양호, 미사용 또는 15분 초과면 취약 (KISA 원문 p.257~258)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `smb_session_policy()`로 이 항목에 필요한 Windows 정보를 읽어 `policy`에 저장한다.
        policy = api.smb_session_policy()
        # `any((value is None for value in policy.values()))` 조건으로 값 부재 또는 지원되지 않는 값을 구분해 오판정을 막는다.
        if any((value is None for value in policy.values())):
            # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
            return _result(item_id, 'UNABLE', 'SMB_SESSION_POLICY_NOT_FOUND', policy, manual_review_required=True)
        # 수집값에서 판정에 필요한 `passed` 값을 계산하거나 골라낸다.
        passed = policy['enable_forced_logoff'] == 1 and int(policy['autodisconnect_minutes']) <= 15
        # 조건이 참이면 KISA 양호 기준을 충족하므로 PASS, 그렇지 않으면 FAIL로 판정하고 판정값을 증적에 담는다.
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W56_SMB_SESSION', policy)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
