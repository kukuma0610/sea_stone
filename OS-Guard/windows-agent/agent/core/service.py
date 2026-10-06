"""중앙 API 어댑터가 호출하는 로컬 Agent 서비스. HTTP 계약은 정의하지 않는다."""

from copy import deepcopy
from dataclasses import asdict, replace

from ..checks.common import WINDOWS_CHECKS, _result
from ..windows_checks import collect_check
from ..hardening import HardeningMode, HardeningRunner, HardeningState, create_plan
from .state import CoreState


class CoreRejected(ValueError):
    pass


class AgentCore:
    def __init__(self, state=None, *, checker=collect_check, runner_factory=HardeningRunner):
        self._state = state if state is not None else CoreState()
        self._checker = checker
        self._runner = runner_factory(self._state.gate, checker=checker)

    def dispatch(self, operation: str, *, job_id: str, **fields) -> dict:
        handlers = {
            "CHECK_WINDOWS": (self.check_windows, set()),
            "CREATE_HARDENING_PLAN": (self.create_hardening_plan, {"code"}),
            "APPROVE_HARDENING": (self.approve_hardening, {"plan_id", "approved"}),
            "RUN_HARDENING": (self.run_hardening, {"plan_id"}),
        }
        if operation not in handlers:
            raise CoreRejected("unsupported Core operation")
        handler, required = handlers[operation]
        if set(fields) != required:
            raise CoreRejected("unexpected or missing operation fields")
        return handler(job_id=job_id, **fields)

    @staticmethod
    def _validate_id(value):
        if not isinstance(value, str) or not value.strip() or len(value) > 128:
            raise CoreRejected("invalid identifier")

    def check_windows(self, *, job_id: str) -> dict:
        self._validate_id(job_id)
        with self._state.lock:
            if job_id in self._state.jobs:
                return deepcopy(self._state.jobs[job_id])
            observations = []
            for number in range(1, 65):
                code = f"W-{number:02d}"
                try:
                    observation = self._checker(code)
                except Exception as exc:
                    observation = _result(
                        code, "UNABLE", "WINDOWS_API_UNAVAILABLE", {},
                        manual_review_required=True, error_reason=type(exc).__name__,
                    )
                observations.append(asdict(observation))
            response = {"job_id": job_id, "checks": observations}
            self._state.jobs[job_id] = response
            return deepcopy(response)

    def create_hardening_plan(self, *, job_id: str, code: str) -> dict:
        self._validate_id(job_id)
        if code not in WINDOWS_CHECKS:
            raise CoreRejected("unsupported W-code")
        with self._state.lock:
            if job_id not in self._state.jobs:
                raise CoreRejected("CHECK job does not exist")
            for plan_id, owner in self._state.plan_jobs.items():
                if owner == job_id and self._state.plans[plan_id].code == code:
                    return self._plan_response(job_id, self._state.plans[plan_id])
            observation = next(row for row in self._state.jobs[job_id]["checks"] if row["item_id"] == code)
            plan = create_plan(observation)
            if plan.mode is HardeningMode.SEMI_AUTO:
                plan = self._state.gate.request(plan)
            self._state.plans[plan.plan_id] = plan
            self._state.plan_jobs[plan.plan_id] = job_id
            return self._plan_response(job_id, plan)

    @staticmethod
    def _plan_response(job_id, plan):
        return deepcopy({"job_id": job_id, "plan": asdict(plan)})

    def _plan(self, job_id, plan_id):
        self._validate_id(job_id)
        self._validate_id(plan_id)
        if self._state.plan_jobs.get(plan_id) != job_id:
            raise CoreRejected("plan does not belong to this job")
        return self._state.plans[plan_id]

    def approve_hardening(self, *, job_id: str, plan_id: str, approved: bool) -> dict:
        if approved is not True:
            raise CoreRejected("explicit boolean approval is required")
        with self._state.lock:
            plan = self._plan(job_id, plan_id)
            if plan.mode is HardeningMode.MANUAL:
                return self._plan_response(job_id, plan)
            plan, receipt = self._state.gate.approve(plan, approved=True)
            self._state.plans[plan_id] = plan
            self._state.receipts[plan_id] = receipt
            return self._plan_response(job_id, plan)

    def run_hardening(self, *, job_id: str, plan_id: str) -> dict:
        with self._state.lock:
            plan = self._plan(job_id, plan_id)
            if plan.mode is HardeningMode.MANUAL:
                return self._plan_response(job_id, plan)
            if plan_id in self._state.results:
                return deepcopy(self._state.results[plan_id])
            if plan.state is not HardeningState.APPROVED or plan_id not in self._state.receipts:
                raise CoreRejected("plan is not approved")
            receipt = self._state.receipts.pop(plan_id)
            self._state.plans[plan_id] = replace(plan, state=HardeningState.RUNNING)
            try:
                result = self._runner.run(plan, receipt)
            except Exception:
                # 실제 변경 여부를 추측하지 않고 실패 상태로 잠근다. 자동 재시도하지 않는다.
                self._state.plans[plan_id] = replace(plan, state=HardeningState.FAILED)
                raise
            self._state.plans[plan_id] = replace(plan, state=result.state)
            response = {"job_id": job_id, "result": asdict(result)}
            self._state.results[plan_id] = response
            return deepcopy(response)
