"""계약 필드·로컬 manifest·lease·증적 projection. OS 판정은 변경하지 않는다."""

from datetime import datetime, timezone
import hashlib
import json
import math
import re
import time
import uuid

from ..checks import CHECK_REGISTRY


class ContractError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError()
        return result
    except (AttributeError, TypeError, ValueError):
        raise ContractError("invalid timezone-aware timestamp") from None


def text(value):
    if not isinstance(value, str) or not value.strip():
        raise ContractError("required identity is missing")
    return value


def envelope(agent_id=None):
    value = {"schema_version": "2.0", "message_id": str(uuid.uuid4()),
             "sent_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    if agent_id is not None:
        value["agent_id"] = text(agent_id)
    return value


def reject_execution_fields(value):
    forbidden = {"command", "cmd", "script", "scriptbody", "powershell", "shell", "argv", "args", "scripturl", "modulepath", "remotescripturl"}
    if isinstance(value, dict):
        for key, item in value.items():
            if re.sub(r"[^a-z]", "", str(key).lower()) in forbidden:
                raise ContractError("remote execution fields are forbidden")
            reject_execution_fields(item)
    elif isinstance(value, list):
        for item in value: reject_execution_fields(item)


class Manifest:
    def __init__(self, value):
        if value.get("schema_version") != "1.0" or value.get("platform") != "windows":
            raise ContractError("approved Windows manifest schema is required")
        self.id = text(value.get("manifest_id"))
        self.version = text(value.get("module_version"))
        if "mock" in self.version.casefold() or value.get("simulation") is True:
            raise ContractError("actual approved module version is required")
        rows = value.get("items")
        if not isinstance(rows, list): raise ContractError("manifest items are missing")
        self.items = {}
        for row in rows:
            code = row.get("item_id")
            if (code not in CHECK_REGISTRY or code in self.items or row.get("implemented") is not True
                    or row.get("module") != f"agent.checks.w{code[2:]}"
                    or row.get("actions") != ["CHECK"]):
                raise ContractError("manifest must use trusted local CHECK mapping")
            self.items[code] = row
        if set(self.items) != set(CHECK_REGISTRY):
            raise ContractError("approved manifest must cover all 64 checks")
        self.supported_os = value.get("supported_os")
        if not isinstance(self.supported_os, list) or not self.supported_os:
            raise ContractError("approved supported OS declarations are required")
        if any(not isinstance(rule, dict) or rule.get("family") != "WINDOWS"
               or not all(isinstance(rule.get(key), str) and rule[key] for key in ("version", "build", "architecture"))
               for rule in self.supported_os):
            raise ContractError("supported OS requires explicit family/version/build/architecture")

    def supports(self, os_info):
        return any(isinstance(rule, dict) and rule and all(os_info.get(key) == val for key, val in rule.items())
                   for rule in self.supported_os)


class Lease:
    def __init__(self, clock=time.monotonic):
        self.clock, self.deadline = clock, 0.0

    def update(self, response, started):
        server = timestamp(response.get("server_time"))
        until = timestamp(response.get("lease_until"))
        duration = response.get("lease_duration_sec")
        if type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0:
            raise ContractError("invalid lease duration")
        if abs(max(0, (until-server).total_seconds())-duration) > 0.01:
            raise ContractError("inconsistent Central lease timing")
        # RTT를 모두 차감한다. 로컬 wall clock과 비교하거나 120초로 초기화하지 않는다.
        received = self.clock()
        self.deadline = received + max(0, duration - max(0, received-started))

    def require(self):
        if self.clock() >= self.deadline:
            raise ContractError("lease expired or unconfirmed")


def validate_task(task, credential, manifest):
    reject_execution_fields(task)
    if (task.get("schema_version") != "2.0" or task.get("action") != "CHECK"
            or task.get("scan_scope") not in {"FULL", "PARTIAL"} or task.get("simulation") is not False
            or task.get("execution_phase") != "CHECK" or task.get("settings") != {}
            or task.get("backup_id") is not None
            or task.get("authorization") != {"grant_id": None, "approval_id": None}):
        raise ContractError("only actual read-only CHECK tasks are accepted")
    for field in ("job_id", "scan_run_id", "attempt_id", "criteria_snapshot_id"):
        text(task.get(field))
    for field in ("agent_id", "server_id"):
        if task.get(field) != credential[field]: raise ContractError("task identity mismatch")
    if task.get("manifest_id") != manifest.id or task.get("module_version") != manifest.version:
        raise ContractError("task release mismatch")
    items, completed = task.get("item_ids"), task.get("completed_item_ids")
    if (not isinstance(items, list) or not items or not all(isinstance(code, str) and code in manifest.items for code in items)
            or len(set(items)) != len(items) or type(task.get("planned_item_count")) is not int
            or task["planned_item_count"] != len(items)):
        raise ContractError("task item plan is invalid")
    if (not isinstance(completed, list) or not all(isinstance(code, str) for code in completed)
            or len(set(completed)) != len(completed) or not set(completed) <= set(items)):
        raise ContractError("completed item list is invalid")
    if task["scan_scope"] == "FULL" and set(items) != set(manifest.items):
        raise ContractError("FULL plan must contain 64 items")
    if timestamp(task.get("expires_at")) < timestamp(task.get("lease_until")):
        raise ContractError("task expiry is before lease")
    return [code for code in items if code not in completed]


def safe_observation(value, tokens=()):
    # 승인된 정책 boolean과 W-47 관측 구조는 key/type 의미를 그대로 유지한다.
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            secret_name = re.search(r"password|secret|token|credential|private.?key|authorization", key, re.I)
            allowed = key in {"password_protected", "password_policy_enabled"} and type(item) is bool
            structured = (key == "password_protected" and isinstance(item, dict)
                          and set(item) <= {"state", "value", "error_reason"}
                          and item.get("state") in {"present", "absent", "error"}
                          and (item.get("value") is None or type(item.get("value")) is bool))
            result[key] = "[REDACTED]" if secret_name and not (allowed or structured) else safe_observation(item, tokens)
        return result
    if isinstance(value, (list, tuple)): return [safe_observation(item, tokens) for item in value]
    if isinstance(value, str):
        if (any(token and token in value for token in tokens) or re.search(
                r"Bearer\s+\S+|-----BEGIN .*PRIVATE KEY|(?:password|token|secret)\s*[:=]", value, re.I)):
            return "[REDACTED]"
    return value
