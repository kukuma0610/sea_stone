"""W-41 read-only CHECK implementation."""

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

CHECK_ID = "W-41"


# `NTP 및 시각 동기화 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “NTP 및 시각 동기화를 설정하면 양호, 미설정이면 취약 (KISA 원문 p.237~238)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `time_sync_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `inventory`에 저장한다.
        inventory = api.time_sync_inventory()
        # 수집값에서 판정에 필요한 `sync_type` 값을 계산하거나 골라낸다.
        sync_type = inventory['sync_type'].casefold()
        # 수집값에서 판정에 필요한 `configured` 값을 계산하거나 골라낸다.
        configured = bool(inventory['service_running']) and sync_type not in {'', 'nosync'} and (sync_type == 'nt5ds' or bool(inventory['ntp_server_configured']))
        # 조건이 참이면 KISA 양호 기준을 충족하므로 PASS, 그렇지 않으면 FAIL로 판정하고 판정값을 증적에 담는다.
        return _result(item_id, 'PASS' if configured else 'FAIL', 'KISA_W41_TIME_SYNC', inventory)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
