"""W-30 read-only CHECK implementation."""

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

CHECK_ID = "W-30"


# `SNMP Community String 복잡성 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “SNMP 미사용 또는 Community String이 public/private가 아니면 양호. 실행 중 public/private 사용 시 취약 (KISA 원문 p.221)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `snmp_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `snmp`에 저장한다.
        snmp = api.snmp_inventory()
        # `not snmp['service_running']` 조건으로 대상이 없거나 기능이 꺼진 상태인지 확인한다.
        if not snmp['service_running']:
            # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'PASS', 'KISA_W30_SNMP_NOT_RUNNING', {'service_running': False})
        # 수집값이 `snmp['community_count'] == 0` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if snmp['community_count'] == 0:
            # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
            return _result(item_id, 'UNABLE', 'SNMP_COMMUNITY_NOT_FOUND', {'service_running': True}, manual_review_required=True)
        # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
        return _result(item_id, 'FAIL' if snmp['default_community_count'] else 'PASS', 'KISA_W30_COMMUNITY_COMPLEXITY', {'service_running': True, 'community_count': snmp['community_count'], 'default_community_count': snmp['default_community_count']})
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
