"""W-60 read-only CHECK implementation."""

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

CHECK_ID = "W-60"


# `보안 채널 데이터 디지털 암호화 또는 서명` 항목을 읽기 전용으로 점검한다. KISA 기준은 “도메인 구성원의 관련 3개 정책이 모두 사용이면 양호, 일부 미사용이면 취약 (KISA 원문 p.265~266)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `secure_channel_policy()`로 이 항목에 필요한 Windows 정보를 읽어 `policy`에 저장한다.
        policy = api.secure_channel_policy()
        # `not policy['domain_joined']` 조건으로 대상이 없거나 기능이 꺼진 상태인지 확인한다.
        if not policy['domain_joined']:
            # KISA 적용 조건에 해당하지 않는 것이 코드로 확인되어 NA를 반환한다.
            return _result(item_id, 'NA', 'KISA_W60_NOT_DOMAIN_MEMBER', {'domain_joined': False})
        # 수집값에서 판정에 필요한 `values` 값을 계산하거나 골라낸다.
        values = [policy['require_sign_or_seal'], policy['seal_secure_channel'], policy['sign_secure_channel']]
        # `any((value is None for value in values))` 조건으로 값 부재 또는 지원되지 않는 값을 구분해 오판정을 막는다.
        if any((value is None for value in values)):
            # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
            return _result(item_id, 'UNABLE', 'SECURE_CHANNEL_POLICY_NOT_FOUND', policy, manual_review_required=True)
        # 조건이 참이면 KISA 양호 기준을 충족하므로 PASS, 그렇지 않으면 FAIL로 판정하고 판정값을 증적에 담는다.
        return _result(item_id, 'PASS' if all((value == 1 for value in values)) else 'FAIL', 'KISA_W60_SECURE_CHANNEL', policy)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
