"""CHECK 결과를 변경 없는 하드닝 계획으로 변환한다."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any
from uuid import uuid4

from ..checks.common import KISA_SOURCES, WINDOWS_CHECKS
from .models import HardeningMode, HardeningPlan
from .registry import SEMI_AUTO_ALLOWLIST


class PlanningRejected(ValueError):
    pass


_ACTION_SUMMARIES = {
    "W-07": "익명 사용자에게 Everyone 권한을 적용하지 않도록 고정 정책값을 설정",
    "W-13": "빈 암호 로컬 계정의 콘솔 외 로그온을 제한하도록 고정 정책값을 설정",
    "W-15": "개인 키 사용 시마다 암호를 요구하도록 강력한 키 보호 수준을 설정",
    "W-48": "로그온하지 않은 시스템 종료를 허용하지 않도록 고정 정책값을 설정",
    "W-50": "감사 로그 실패 시 즉시 종료 정책을 사용하지 않도록 고정 정책값을 설정",
    "W-52": "자동 로그온을 사용하지 않도록 고정 정책값을 설정",
    "W-53": "이동식 미디어 포맷·꺼내기 권한을 Administrators로 제한",
    "W-59": "LAN Manager 인증 수준을 NTLMv2 응답만 보내기로 설정",
}


def _observation_values(observation: Any) -> tuple[str, str, dict[str, Any]]:
    if is_dataclass(observation):
        values = asdict(observation)
    elif isinstance(observation, dict):
        values = observation
    else:
        raise TypeError("observation must be a CHECK result or dictionary")
    code = str(values.get("item_id", ""))
    status = str(values.get("status", ""))
    current = values.get("current_value", values.get("evidence", {}))
    if not isinstance(current, dict):
        raise TypeError("CHECK evidence must be a dictionary")
    return code, status, current


def create_plan(observation: Any) -> HardeningPlan:
    code, status, current = _observation_values(observation)
    if code not in WINDOWS_CHECKS:
        raise PlanningRejected("unsupported W-code")
    if status != "FAIL":
        raise PlanningRejected("only FAIL results can produce a hardening plan")

    source = KISA_SOURCES[code]
    criteria = (
        f"양호: {source['good']} / 취약: {source['bad']} "
        f"(KISA p.{source['page']})"
    )
    if code in SEMI_AUTO_ALLOWLIST:
        return HardeningPlan(
            plan_id=str(uuid4()), code=code, mode=HardeningMode.SEMI_AUTO,
            current_status=status, approval_required=True, approved=False,
            action_summary=_ACTION_SUMMARIES[code], manual_required=False,
            kisa_criteria=criteria, current_value=current,
        )

    guide = f"현재 증적과 {criteria}을 검토한 뒤, 승인된 운영 절차에 따라 {code} 항목을 관리자가 직접 조치한다."
    return HardeningPlan(
        plan_id=str(uuid4()), code=code, mode=HardeningMode.MANUAL,
        current_status=status, approval_required=False, approved=False,
        action_summary="운영 영향과 적용 범위를 확인한 후 관리자가 직접 조치",
        manual_required=True, manual_guide=guide,
        kisa_criteria=criteria, current_value=current,
    )


def create_plans(observations: list[Any]) -> list[HardeningPlan]:
    plans: list[HardeningPlan] = []
    for observation in observations:
        try:
            plans.append(create_plan(observation))
        except PlanningRejected as exc:
            if str(exc) != "only FAIL results can produce a hardening plan":
                raise
    return plans
