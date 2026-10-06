"""W-17 read-only CHECK implementation."""

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

CHECK_ID = "W-17"


# `하드디스크 기본 공유 제거` 항목을 읽기 전용으로 점검한다. KISA 기준은 “양호: AutoShareServer 0이고 기본 공유 없음. 취약: 값 1 또는 기본 공유 존재. 원문 p.198~199”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `autoshare_server()`로 이 항목에 필요한 Windows 정보를 읽어 `autoshare`에 저장한다.
        autoshare = api.autoshare_server()
        # 공통 수집기의 `shares()`로 이 항목에 필요한 Windows 정보를 읽어 `default_shares`에 저장한다.
        default_shares = [share for share in api.shares() if share['name'].upper() == 'ADMIN$' or re.fullmatch('[A-Z]\\$', share['name'].upper())]
        # 수집값에서 판정에 필요한 `passed` 값을 계산하거나 골라낸다.
        passed = autoshare == 0 and (not default_shares)
        # 조건이 참이면 KISA 양호 기준을 충족하므로 PASS, 그렇지 않으면 FAIL로 판정하고 판정값을 증적에 담는다.
        return _result(item_id, 'PASS' if passed else 'FAIL', 'KISA_W17_DEFAULT_SHARES', {'autoshare_server': autoshare, 'default_share_count': len(default_shares)})
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
