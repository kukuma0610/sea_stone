"""명시적 승인을 소비한 뒤 allowlist action만 실행하는 하드닝 실행기."""

from __future__ import annotations

import ctypes
import os
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from ..windows_checks import collect_check
from .models import (
    ApprovalReceipt, HardeningMode, HardeningPlan, HardeningResult,
    HardeningState, RegistrySnapshot, RollbackResult,
)
from .registry import get_action
from .snapshots import SnapshotError, SnapshotStore


class HardeningRejected(RuntimeError):
    pass


class ApprovalGate:
    """승인 요청과 승인을 분리하고, 승인 영수증을 실행 시 한 번만 소비한다."""

    def __init__(self) -> None:
        self._receipts: dict[str, ApprovalReceipt] = {}

    def request(self, plan: HardeningPlan) -> HardeningPlan:
        if plan.mode is not HardeningMode.SEMI_AUTO or plan.state is not HardeningState.PLANNED:
            raise HardeningRejected("only a planned SEMI_AUTO action can request approval")
        return replace(plan, state=HardeningState.WAITING_APPROVAL)

    def approve(self, plan: HardeningPlan, *, approved: bool) -> tuple[HardeningPlan, ApprovalReceipt]:
        if not approved:
            raise HardeningRejected("explicit approval was not granted")
        if plan.state is not HardeningState.WAITING_APPROVAL:
            raise HardeningRejected("plan is not waiting for approval")
        receipt = ApprovalReceipt(str(uuid4()), plan.plan_id, plan.code)
        self._receipts[receipt.receipt_id] = receipt
        return replace(plan, state=HardeningState.APPROVED, approved=True), receipt

    def consume(self, plan: HardeningPlan, receipt: ApprovalReceipt) -> None:
        if not isinstance(receipt, ApprovalReceipt):
            raise HardeningRejected("approval receipt is missing, invalid, or already used")
        stored = self._receipts.pop(receipt.receipt_id, None)
        if stored != receipt or receipt.plan_id != plan.plan_id or receipt.code != plan.code:
            raise HardeningRejected("approval receipt is missing, invalid, or already used")


def _is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class HardeningRunner:
    def __init__(
        self,
        gate: ApprovalGate,
        *,
        checker: Callable[[str, Any | None], Any] = collect_check,
        administrator_check: Callable[[], bool] = _is_administrator,
        api: Any | None = None,
        snapshot_store: SnapshotStore | None = None,
    ) -> None:
        self._gate = gate
        self._checker = checker
        self._administrator_check = administrator_check
        self._api = api
        self._snapshot_store = snapshot_store or SnapshotStore()

    def run(self, plan: HardeningPlan, receipt: ApprovalReceipt) -> HardeningResult:
        if plan.mode is HardeningMode.MANUAL or plan.manual_required:
            raise HardeningRejected("MANUAL plans provide guidance and cannot change the system")
        if plan.state is not HardeningState.APPROVED or not plan.approved:
            raise HardeningRejected("hardening requires an approved plan")
        if not self._administrator_check():
            raise HardeningRejected("administrator privileges are required")

        action = get_action(plan.code)
        self._gate.consume(plan, receipt)
        history = (
            HardeningState.PLANNED, HardeningState.WAITING_APPROVAL,
            HardeningState.APPROVED, HardeningState.RUNNING,
        )
        before_action: dict[str, Any] = {}
        before_check: dict[str, Any] = {}
        snapshot: RegistrySnapshot | None = None
        try:
            before_observation = self._checker(plan.code, self._api)
            before_check = asdict(before_observation)
            if before_check["status"] != "FAIL":
                raise HardeningRejected("current CHECK result is no longer FAIL")
            before_action = action.capture()
            snapshot = self._snapshot_store.create(
                code=plan.code, plan_id=plan.plan_id, path=action.path,
                value_name=action.name, captured=before_action,
            )
            action.apply()
            after_action = action.capture()
            after_observation = self._checker(plan.code, self._api)
            after_check = asdict(after_observation)
            if after_check["status"] != "PASS":
                raise HardeningRejected("CHECK did not transition to PASS after hardening")
            changed = before_action != after_action
            return HardeningResult(
                plan_id=plan.plan_id, code=plan.code, state=HardeningState.SUCCESS,
                before={"setting": before_action, "check": before_check},
                after={"setting": after_action, "check": after_check},
                changed=changed, pass_transition=after_check["status"] == "PASS",
                state_history=history + (HardeningState.SUCCESS,),
                snapshot_id=snapshot.snapshot_id,
            )
        except Exception as exc:
            rollback = None
            if snapshot is not None:
                rollback = self._perform_rollback(snapshot, action)
            return HardeningResult(
                plan_id=plan.plan_id, code=plan.code, state=HardeningState.FAILED,
                before={"setting": before_action, "check": before_check}, after=None,
                changed=False, pass_transition=False,
                state_history=history + (HardeningState.FAILED,),
                error_reason=f"{type(exc).__name__}: {exc}",
                snapshot_id=snapshot.snapshot_id if snapshot else None,
                rollback=rollback,
            )

    def rollback(self, *, code: str, snapshot_id: str, plan_id: str) -> RollbackResult:
        if not self._administrator_check():
            raise HardeningRejected("administrator privileges are required")
        try:
            snapshot = self._snapshot_store.load(snapshot_id)
        except SnapshotError as exc:
            raise HardeningRejected(str(exc)) from exc
        if snapshot.code != code or snapshot.plan_id != plan_id:
            raise HardeningRejected("snapshot does not belong to this W-code and plan")
        if self._snapshot_store.has_successful_rollback(snapshot_id):
            raise HardeningRejected("snapshot has already been rolled back")
        action = get_action(code)
        return self._perform_rollback(snapshot, action)

    def _perform_rollback(self, snapshot: RegistrySnapshot, action: Any) -> RollbackResult:
        if action.code != snapshot.code or action.path != snapshot.registry_path or action.name != snapshot.value_name:
            raise HardeningRejected("snapshot registry target does not match the allowlisted action")
        restored = None
        check_result = None
        error_reason = None
        success = False
        try:
            action.restore(asdict(snapshot))
            restored = action.capture()
            check_result = asdict(self._checker(snapshot.code, self._api))
            success = True
        except Exception as exc:
            error_reason = f"{type(exc).__name__}: {exc}"
        result = RollbackResult(
            snapshot_id=snapshot.snapshot_id, plan_id=snapshot.plan_id,
            code=snapshot.code, success=success, restored_setting=restored,
            check_result=check_result, timestamp=datetime.now(timezone.utc).isoformat(),
            error_reason=error_reason,
        )
        self._snapshot_store.record_rollback(result)
        return result
