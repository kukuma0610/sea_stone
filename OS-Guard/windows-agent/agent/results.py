import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class WindowsEvidence:
    evidence_id: str
    server_id: str
    scan_run_id: str
    item_id: str
    collector_id: str
    captured_at: str
    media_type: str = "application/json"
    redacted: bool = True
    sha256: str | None = None
    byte_length: int | None = None
    storage_ref: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "server_id": self.server_id,
            "scan_run_id": self.scan_run_id,
            "item_id": self.item_id,
            "collector_id": self.collector_id,
            "captured_at": self.captured_at,
            "redacted": self.redacted,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "storage_ref": self.storage_ref,
        }


@dataclass(frozen=True)
class WindowsCheckResult:
    agent_id: str
    server_id: str
    job_id: str
    scan_run_id: str
    attempt_id: str
    item_id: str
    criteria_snapshot_id: str
    status: str | None = None
    review_state: str = "PENDING"
    auto_stage_state: str = "MOCK_ONLY"
    reason_code: str = "MOCK_NOT_IMPLEMENTED"
    observed_at: str = field(default_factory=_now)
    evidence_ids: tuple[str, ...] = ()
    current_value: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] | None = None
    result_id: str = field(default_factory=lambda: f"res-{uuid.uuid4()}")

    def __post_init__(self) -> None:
        if not self.item_id.startswith("W-"):
            raise ValueError("Windows CHECK result requires a W-* item_id")
        if self.review_state == "CONFIRMED":
            raise ValueError("Agent cannot submit CONFIRMED results")

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "message_id": f"msg-{uuid.uuid4()}",
            "sent_at": _now(),
            "agent_id": self.agent_id,
            "server_id": self.server_id,
            "job_id": self.job_id,
            "scan_run_id": self.scan_run_id,
            "attempt_id": self.attempt_id,
            "result_id": self.result_id,
            "item_id": self.item_id,
            "criteria_snapshot_id": self.criteria_snapshot_id,
            "status": self.status,
            "review_state": self.review_state,
            "auto_stage_state": self.auto_stage_state,
            "reason_code": self.reason_code,
            "observed_at": self.observed_at,
            "evidence_ids": list(self.evidence_ids),
            "current_value": self.current_value,
            "error": self.error,
        }


def build_mock_check_result(identity: Any, task: dict[str, Any]) -> WindowsCheckResult:
    """Build a transport-only result; it does not inspect or change Windows."""
    return WindowsCheckResult(
        agent_id=identity.agent_id,
        server_id=str(task.get("server_id", "srv-win-mock")),
        job_id=str(task["job_id"]),
        scan_run_id=str(task["scan_run_id"]),
        attempt_id=str(task["attempt_id"]),
        item_id=str(task.get("item_ids", ["W-01"])[0]),
        criteria_snapshot_id=str(task.get("criteria_snapshot_id", "criteria-win-mock")),
        evidence_ids=("ev-win-mock",),
        current_value={"mock": True, "checked": False},
    )


def build_check_result(identity: Any, task: dict[str, Any], observation: Any) -> WindowsCheckResult:
    """Map a read-only collector observation to the existing result envelope."""
    current_value = dict(observation.current_value)
    current_value["manual_review_required"] = bool(observation.manual_review_required)
    return WindowsCheckResult(
        agent_id=identity.agent_id,
        server_id=str(task["server_id"]),
        job_id=str(task["job_id"]),
        scan_run_id=str(task["scan_run_id"]),
        attempt_id=str(task["attempt_id"]),
        item_id=observation.item_id,
        criteria_snapshot_id=str(task["criteria_snapshot_id"]),
        status=observation.status,
        reason_code=observation.reason_code,
        observed_at=observation.observed_at,
        current_value=current_value,
        error={"error_reason": observation.error_reason} if observation.error_reason else None,
    )
