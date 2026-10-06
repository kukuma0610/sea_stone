"""W-42 read-only CHECK implementation."""

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

CHECK_ID = "W-42"


# `이벤트 로그 관리 설정` 항목을 읽기 전용으로 점검한다. KISA 기준은 “최대 로그 10,240KB 이상 및 90일 이후 덮어쓰기면 양호, 용량 미달 또는 90일 이하 덮어쓰기면 취약 (KISA 원문 p.239)”이다.
def check(api: Any | None = None) -> CheckObservation:
    item_id = CHECK_ID
    try:
        # 테스트에서 전달한 수집기가 없으면 실제 Windows 읽기 전용 수집기를 준비한다.
        api = api or NativeWindowsReadOnlyApi()
        # 공통 수집기의 `event_log_inventory()`로 이 항목에 필요한 Windows 정보를 읽어 `logs`에 저장한다.
        logs = api.event_log_inventory()
        # 수집값에서 판정에 필요한 `undersized_count` 값을 계산하거나 골라낸다.
        undersized_count = sum((int(log['maximum_size_kb']) < 10240 for log in logs))
        # 수집값에서 판정에 필요한 `evidence` 값을 계산하거나 골라낸다.
        evidence = {'log_count': len(logs), 'undersized_log_count': undersized_count, 'logs': [{'name': log['name'], 'maximum_size_kb': int(log['maximum_size_kb']), 'log_mode': log['log_mode']} for log in logs]}
        # 수집값이 `undersized_count` 조건을 만족하는지 비교해 다음 판정 분기를 선택한다.
        if undersized_count:
            # 이 분기에서는 KISA 취약 조건이 확인되었으므로 FAIL을 반환하며, 함께 전달한 값은 판정 증적이다.
            return _result(item_id, 'FAIL', 'KISA_W42_LOG_SIZE', evidence)
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'EVENT_RETENTION_DAYS_NOT_AVAILABLE_ON_SERVER_2022', evidence, manual_review_required=True)
    # Windows API 호출, 권한, 자료형 또는 필수 키 오류가 나면 정확한 판정이 불가능하므로 이 항목만 UNABLE로 처리한다.
    except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
        # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
        return _result(item_id, 'UNABLE', 'WINDOWS_API_UNAVAILABLE', {}, manual_review_required=True, error_reason=str(exc))
    # 필요한 값이나 자동판정 근거가 부족하므로 추측하지 않고 UNABLE을 반환한다. 수동 검토 여부와 오류 사유도 결과에 보존한다.
    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
