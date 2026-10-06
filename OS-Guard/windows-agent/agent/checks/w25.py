"""W-25 read-only CHECK implementation."""

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

CHECK_ID = "W-25"


# `DNS Zone Transfer 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: DNS 비활성화, 전송 차단 또는 특정 서버 제한. 취약: 그 외 설정. 원문 p.214~215”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `dns_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `dns`에 저장한다.
        dns = api.dns_inventory()
        # `not dns['service_running']` 조건으로 대상이 없거나 기능이 꺼진 상태인지 확인한다.
        if not dns['service_running']:
            # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'PASS', 'KISA_W25_DNS_NOT_RUNNING', {'service_running': False, 'zone_count': 0})
        # 수집값에서 판정에 필요한 `allowed` 값을 계산하거나 골라낸다.
        allowed = {'NoTransfer', 'TransferToZoneNameServer', 'TransferToSecureServers'}
        # 수집값에서 판정에 필요한 `denied` 값을 계산하거나 골라낸다.
        denied = {'TransferToAnyServer'}
        # 수집값에서 판정에 필요한 `transfer_types` 값을 계산하거나 골라낸다.
        transfer_types = [zone['transfer_type'] for zone in dns['zones']]
        # `any((value not in allowed | denied for value in transfer_types))` 조건으로 값 부재 또는 지원되지 않는 값을 구분해 오판정을 막는다.
        if any((value not in allowed | denied for value in transfer_types)):
            # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
            return _result(item_id, 'UNABLE', 'DNS_TRANSFER_TYPE_UNRECOGNIZED', {'service_running': True, 'zone_count': len(transfer_types)}, manual_review_required=True)
        # 수집값에서 판정에 필요한 `insecure_count` 값을 계산하거나 골라낸다.
        insecure_count = sum((value in denied for value in transfer_types))
        # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
        return _result(item_id, 'FAIL' if insecure_count else 'PASS', 'KISA_W25_ZONE_TRANSFER', {'service_running': True, 'zone_count': len(transfer_types), 'insecure_zone_count': insecure_count})
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
