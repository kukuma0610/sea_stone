"""W-24 read-only CHECK implementation."""

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

CHECK_ID = "W-24"


# `FTP 접근 제어 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: 특정 IP만 FTP 접속 허용. 취약: 특정 IP 접근 제어 미적용. 원문 p.212~213”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 수집값에서 판정에 필요한 `ftp` 값을 계산하거나 골라낸다.
        ftp = getattr(api, "ftp_check_inventory", api.ftp_inventory)()
        # 수집값에서 판정에 필요한 `sites` 값을 계산하거나 골라낸다.
        sites = ftp['sites']
        # `not sites` 조건으로 대상이 없거나 기능이 꺼진 상태인지 확인한다.
        if not sites:
            # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
            return _result(item_id, 'UNABLE', 'FTP_SITE_NOT_CONFIGURED', {'site_count': 0}, manual_review_required=True,
                           error_reason="No FTP sites available for IP access control verification")
        # 수집값에서 판정에 필요한 `unrestricted_count` 값을 계산하거나 골라낸다.
        unrestricted_count = sum((bool(site['ip_allow_unlisted']) or int(site['ip_allow_count']) == 0 for site in sites))
        # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
        return _result(item_id, 'FAIL' if unrestricted_count else 'PASS', 'KISA_W24_FTP_IP_RESTRICTION', {'site_count': len(sites), 'unrestricted_site_count': unrestricted_count})
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
