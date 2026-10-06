"""W-54 read-only CHECK implementation."""

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

CHECK_ID = "W-54"


# `DoS 공격 방어 레지스트리 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “SynAttackProtect≥1, EnableDeadGWDetect=0, KeepAliveTime=300000, NoNameReleaseOnDemand=1이면 양호, 미설정이면 취약 (KISA 원문 p.255)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `dos_defense_registry()`로 이 항목에 필요한 Windows 정보를 읽어 `values`에 저장한다.
        values = api.dos_defense_registry()
        # `any((value is None for value in values.values()))` 조건으로 값 부재 또는 지원되지 않는 값을 구분해 오판정을 막는다.
        if any((value is None for value in values.values())):
            # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'FAIL', 'KISA_W54_DOS_REGISTRY_NOT_CONFIGURED', values)
        # 수집값에서 판정에 필요한 `passed` 값을 계산하거나 골라낸다.
        passed = int(values['SynAttackProtect']) >= 1 and values['EnableDeadGWDetect'] == 0 and (values['KeepAliveTime'] == 300000) and (values['NoNameReleaseOnDemand'] == 1)
        # 수집값이 `passed` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if passed:
            # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'PASS', 'KISA_W54_DOS_REGISTRY', values)
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'DOS_REGISTRY_VALUES_OUTSIDE_DOCUMENTED_DECISION', values, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
