"""W-19 read-only CHECK implementation."""

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

CHECK_ID = "W-19"


# `불필요한 IIS 서비스 구동 점검` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: IIS 미사용 또는 필요에 의해 사용. 취약: 불필요하게 사용. 원문 p.204”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `iis_services()`로 이 항목에 필요한 Windows 정보를 읽어 `services`에 저장한다.
        services = api.iis_services()
        # 수집값에서 판정에 필요한 `running` 값을 계산하거나 골라낸다.
        running = [service for service in services if service['status'].lower() == 'running']
        # `not running` 조건으로 대상이 없거나 기능이 꺼진 상태인지 확인한다.
        if not running:
            # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'PASS', 'KISA_W19_IIS_NOT_RUNNING', {'installed_service_count': len(services), 'running_service_count': 0})
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'IIS_NECESSITY_REQUIRES_MANUAL_REVIEW', {'installed_service_count': len(services), 'running_service_count': len(running)}, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
