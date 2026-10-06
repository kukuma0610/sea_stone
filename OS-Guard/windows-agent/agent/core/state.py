"""요청 간 작업과 승인을 공유하는 프로세스 내 저장소."""

from dataclasses import dataclass, field
from threading import RLock
from typing import Any

from ..hardening import ApprovalGate


@dataclass
class CoreState:
    # 같은 저장소의 서비스 요청은 직렬화해 중복 실행과 승인 경합을 막는다.
    lock: Any = field(default_factory=RLock)
    gate: ApprovalGate = field(default_factory=ApprovalGate)
    jobs: dict[str, dict] = field(default_factory=dict)
    plans: dict[str, Any] = field(default_factory=dict)
    plan_jobs: dict[str, str] = field(default_factory=dict)
    receipts: dict[str, Any] = field(default_factory=dict)
    results: dict[str, dict] = field(default_factory=dict)
