import json
import os
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.request import Request, urlopen

from . import MODULE_VERSION
from .identity import AgentIdentity
from .inventory import collect_inventory
from .results import WindowsCheckResult
from .tasks import validate_check_task

ENROLL_PATH = "/agent-api/v2/enrollments"
HEARTBEAT_PATH = "/agent-api/v2/heartbeat"
CLAIM_PATH = "/agent-api/v2/tasks/claim"
RESULTS_PATH = "/agent-api/v2/tasks/{job_id}/results"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Transport(Protocol):
    def post(self, path: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]: ...


class HttpsTransport:
    """HTTPS transport with normal certificate and hostname verification."""

    def __init__(self, base_url: str, timeout: float = 10.0):
        if not base_url.lower().startswith("https://"):
            raise ValueError("central API URL must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def post(self, path: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        # Do not use an unverified context. The default context validates TLS certificates.
        with urlopen(request, timeout=self.timeout, context=ssl.create_default_context()) as response:
            return json.loads(response.read().decode("utf-8"))


class CommunicationError(RuntimeError):
    pass


class AgentClient:
    def __init__(self, identity: AgentIdentity, transport: Transport, module_version: str = MODULE_VERSION):
        self.identity = identity
        self.transport = transport
        self.module_version = module_version
        self._token: str | None = os.environ.get("OS_GUARD_AGENT_TOKEN")

    def enroll(self, enrollment_secret: str | None = None) -> dict[str, Any]:
        headers = {}
        if enrollment_secret:
            headers["X-Agent-Enrollment-Secret"] = enrollment_secret
        payload = {
            "schema_version": "2.0",
            "message_id": f"msg-{uuid.uuid4()}",
            "sent_at": _now(),
            "enrollment_id": self.identity.agent_id,
            "hostname": collect_inventory()["hostname"],
            "agent_version": self.identity.version,
            "os": collect_inventory(),
            "capabilities": ["CHECK"],
        }
        response = self._post(ENROLL_PATH, payload, headers)
        self._token = response.get("token", self._token)
        safe_response = dict(response)
        safe_response.pop("token", None)
        return safe_response

    def heartbeat(self) -> dict[str, Any]:
        payload = {
            "schema_version": "2.0",
            "message_id": f"msg-{uuid.uuid4()}",
            "sent_at": _now(),
            "agent_id": self.identity.agent_id,
            "agent_version": self.identity.version,
            "module_version": self.module_version,
            "inventory_version": "windows-inventory-0.1.0",
            "active_job_id": None,
            "health": "READY",
            "pending_result_count": 0,
        }
        return self._post(HEARTBEAT_PATH, payload, self._auth_headers())

    def claim_check(self) -> dict[str, Any] | None:
        task = self._post(CLAIM_PATH, {"agent_id": self.identity.agent_id}, self._auth_headers())
        if not task:
            return None
        return validate_check_task(task)

    def submit_check_result(self, result: WindowsCheckResult) -> dict[str, Any]:
        return self._post(
            RESULTS_PATH.format(job_id=result.job_id),
            result.to_payload(),
            self._auth_headers(),
        )

    def _post(self, path: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        try:
            return self.transport.post(path, payload, headers)
        except (OSError, TimeoutError) as exc:
            raise CommunicationError("central API communication failed") from exc

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}


class MockApi:
    """In-process Mock API for local tests; not a production server."""

    def __init__(self):
        self.enrolled = False
        self.last_heartbeat: dict[str, Any] | None = None
        self.tasks: list[dict[str, Any]] = []
        self.received_results: dict[str, dict[str, Any]] = {}

    def post(self, path: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        if path == ENROLL_PATH:
            self.enrolled = True
            return {"server_id": "srv-win-mock", "agent_id": "agt-win-mock", "credential_id": "cred-mock", "token": uuid.uuid4().hex, "expires_at": "2099-01-01T00:00:00Z"}
        if path == HEARTBEAT_PATH:
            self.last_heartbeat = payload
            return {"received_at": _now(), "poll_after_sec": 30}
        if path == CLAIM_PATH:
            return self.tasks.pop(0) if self.tasks else {}
        if path.startswith("/agent-api/v2/tasks/") and path.endswith("/results"):
            result_id = payload["result_id"]
            if result_id in self.received_results:
                return {"accepted_ids": [], "duplicate_ids": [result_id]}
            self.received_results[result_id] = payload
            return {"accepted_ids": [result_id], "duplicate_ids": []}
        raise AssertionError(f"unsupported mock path: {path}")
