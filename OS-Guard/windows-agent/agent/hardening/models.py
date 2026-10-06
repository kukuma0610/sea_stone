"""승인 기반 하드닝 계획과 실행 결과 모델."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HardeningMode(str, Enum):
    SEMI_AUTO = "SEMI_AUTO"
    MANUAL = "MANUAL"


class HardeningState(str, Enum):
    PLANNED = "PLANNED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class HardeningPlan:
    plan_id: str
    code: str
    mode: HardeningMode
    current_status: str
    approval_required: bool
    approved: bool
    action_summary: str
    manual_required: bool
    kisa_criteria: str
    current_value: dict[str, Any]
    manual_guide: str | None = None
    state: HardeningState = HardeningState.PLANNED


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    plan_id: str
    code: str


@dataclass(frozen=True)
class HardeningResult:
    plan_id: str
    code: str
    state: HardeningState
    before: dict[str, Any]
    after: dict[str, Any] | None
    changed: bool
    pass_transition: bool
    state_history: tuple[HardeningState, ...] = field(default_factory=tuple)
    error_reason: str | None = None
    snapshot_id: str | None = None
    rollback: "RollbackResult | None" = None


@dataclass(frozen=True)
class RegistrySnapshot:
    snapshot_id: str
    code: str
    registry_path: str
    value_name: str
    value_type: int | None
    previous_value: int | str | None
    existed: bool
    timestamp: str
    plan_id: str


@dataclass(frozen=True)
class RollbackResult:
    snapshot_id: str
    plan_id: str
    code: str
    success: bool
    restored_setting: dict[str, Any] | None
    check_result: dict[str, Any] | None
    timestamp: str
    error_reason: str | None = None
