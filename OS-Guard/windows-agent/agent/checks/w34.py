"""W-34 read-only CHECK implementation."""

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

CHECK_ID = "W-34"


# `Telnet 서비스 비활성화` 항목을 읽기 전용으로 점검한다. KISA 기준은 “Telnet 미구동 또는 NTLM 인증이면 양호, 구동 중 NTLM 외 인증이면 취약. 적용 대상은 Windows 2012까지 (KISA 원문 p.228)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `windows_os_info()`로 이 항목에 필요한 Windows 정보를 읽어 `os_info`에 저장한다.
        os_info = api.windows_os_info()
        # 수집값이 `'Windows Server 2022' in os_info['caption']` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if 'Windows Server 2022' in os_info['caption']:
            # KISA 적용 조건에 해당하지 않는 것이 코드로 확인되어 NA를 반환한다.
            return _result(item_id, 'NA', 'KISA_W34_SERVER_2022_NOT_APPLICABLE', {'caption': os_info['caption']})
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'TELNET_AUTHENTICATION_REQUIRES_APPLICABLE_OS_REVIEW', {'caption': os_info['caption']}, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
