"""W-23 read-only CHECK implementation."""

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

CHECK_ID = "W-23"


# `공유 서비스에 대한 익명 접근 제한 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: 공유 서비스 미사용 또는 익명 인증 비활성화. 취약: 익명 인증 활성화. 원문 p.210~211”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `ftp_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `ftp`에 저장한다.
        ftp = api.ftp_inventory()
        # 수집값에서 판정에 필요한 `anonymous_count` 값을 계산하거나 골라낸다.
        anonymous_count = sum((bool(site['anonymous_enabled']) for site in ftp['sites']))
        # 수집값이 `anonymous_count` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if anonymous_count:
            # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'FAIL', 'KISA_W23_FTP_ANONYMOUS_ENABLED', {'ftp_site_count': len(ftp['sites']), 'anonymous_ftp_site_count': anonymous_count})
        # 공통 수집기의 `shares()`로 이 항목에 필요한 Windows 정보를 읽어 `normal_share_count`에 저장한다.
        normal_share_count = sum((not bool(share['special']) for share in api.shares()))
        # 공통 수집기의 `auxiliary_share_services()`로 이 항목에 필요한 Windows 정보를 읽어 `auxiliary`에 저장한다.
        auxiliary = api.auxiliary_share_services()
        # 수집값이 `normal_share_count or auxiliary` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if normal_share_count or auxiliary:
            # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'FAIL', 'KISA_W23_SHARE_SERVICE_IN_USE', {'ftp_site_count': len(ftp['sites']), 'normal_smb_share_count': normal_share_count, 'auxiliary_share_service_count': len(auxiliary)})
        # 이 분기에서는 KISA 양호 조건이 확인되었으므로 PASS를 반환하며, 함께 전달한 값은 판정 증적이다.
        return _result(item_id, 'PASS', 'KISA_W23_ANONYMOUS_DISABLED', {'ftp_site_count': len(ftp['sites']), 'anonymous_ftp_site_count': 0})
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
