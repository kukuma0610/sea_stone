"""WAC-01~13 운영 흐름. 미합의 실제 릴리스는 Manifest 입력으로만 받는다."""

import base64
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import math
import re
import random
import threading
import time
import uuid
from urllib.parse import quote

from .. import AGENT_VERSION
from ..windows_checks import collect_check
from ..checks.common import _result
from .contract import (ContractError, Lease, canonical, envelope, safe_observation,
                       text, timestamp, validate_task)
from .inventory import collect_snapshot
from .transport import CentralError, normalize_url


class CentralAgent:
    def __init__(self, transport, state, manifest, *, checker=collect_check, inventory=collect_snapshot,
                 retries=5, retry_base=1.0, poll_interval=10.0, lease_renewal_fraction=1/3,
                 clock=time.monotonic, sleep=time.sleep):
        self.transport, self.state, self.manifest = transport, state, manifest
        self.checker, self.inventory = checker, inventory
        if type(retries) is not int or not 0 <= retries <= 10 or not 0 <= retry_base <= 60:
            raise ContractError("invalid bounded retry configuration")
        self.retries, self.retry_base, self.clock, self.sleep = retries, retry_base, clock, sleep
        if (type(poll_interval) not in (int, float) or not 0 < poll_interval <= 60
                or type(lease_renewal_fraction) not in (int, float) or not 0 < lease_renewal_fraction <= 0.5):
            raise ContractError("invalid poll or lease renewal bounds")
        self.poll_interval, self.renewal_fraction = poll_interval, lease_renewal_fraction
        self.lease = Lease(clock)
        self.operation_lock = threading.Lock()
        self.heartbeat_interval = 30.0
        self.background_error = None

    @property
    def credential(self):
        result = self.state.data["credential"]
        if not result: raise ContractError("enrollment is required")
        return result

    def _tokens(self):
        rotation = self.state.data.get("rotation") or {}
        return [row.get("token", "") for row in (self.state.data.get("credential") or {},
                                                  rotation.get("old") or {}, rotation.get("new") or {})]

    def _envelope(self): return envelope(self.credential["agent_id"])

    def _retry_send(self, path, payload, *, token=None, file_bytes=None, deadline=None,
                    enrollment_token=None, retryable=True):
        headers = ({"X-Enrollment-Token": enrollment_token} if enrollment_token is not None else
                   {"Authorization": "Bearer " + (token or self.credential["token"])})
        for attempt in range(self.retries + 1):
            if deadline is not None and self.clock() >= deadline:
                raise ContractError("request cannot start after lease deadline")
            try:
                return self.transport.send(path, payload, headers, file_bytes)
            except CentralError as exc:
                temporary = exc.code == "NETWORK_ERROR" or exc.status == 429 or 500 <= exc.status < 600
                if not retryable or not temporary or attempt == self.retries:
                    raise
                delay = self.retry_base * (2 ** attempt) + random.uniform(0, max(self.retry_base / 4, 0))
                if exc.retry_after is not None:
                    try:
                        delay = max(delay, float(exc.retry_after))
                    except (TypeError, ValueError):
                        from email.utils import parsedate_to_datetime
                        try:
                            delay = max(delay, (parsedate_to_datetime(exc.retry_after)-datetime.now(timezone.utc)).total_seconds())
                        except Exception:
                            raise CentralError("INVALID_RETRY_AFTER", exc.status) from None
                if not math.isfinite(delay) or delay < 0 or delay > 300 or (deadline is not None and self.clock()+delay >= deadline):
                    raise ContractError("retry exceeds allowed time budget")
                self.sleep(delay)

    def _prepare(self, key, path, payload, file_bytes=None, *, save=True):
        with self.state.lock:
            records = self.state.data["outbox"]
            if key not in records:
                records[key] = {"path": path, "payload": deepcopy(payload), "agent_id": self.credential["agent_id"],
                                "bytes": base64.b64encode(file_bytes).decode() if file_bytes is not None else None,
                                "ack": None}
                if save: self.state.save()
            record = records[key]
            if record["path"] != path or record["agent_id"] != self.credential["agent_id"]:
                raise ContractError("pending outbox belongs to another identity or endpoint")
            return record

    def _deliver(self, record, validate, *, deadline=None, replay=False):
        if record["ack"] is not None and not replay: return record["ack"]
        file_bytes = base64.b64decode(record["bytes"]) if record["bytes"] is not None else None
        response = self._retry_send(record["path"], record["payload"], file_bytes=file_bytes, deadline=deadline)
        ack = validate(response, record["payload"])
        with self.state.lock:
            record["ack"] = ack
            self.state.save()
        return ack

    @staticmethod
    def _credential_response(body, server_id=None, agent_id=None):
        if not isinstance(body, dict): raise ContractError("invalid credential response")
        result = {key: text(body.get(key)) for key in ("server_id", "agent_id", "credential_id", "token", "expires_at")}
        if "\r" in result["token"] or "\n" in result["token"]: raise ContractError("invalid operating token")
        timestamp(result["expires_at"])
        if server_id is not None and result["server_id"] != server_id: raise ContractError("server binding mismatch")
        if agent_id is not None and result["agent_id"] != agent_id: raise ContractError("agent binding mismatch")
        return result

    def enroll(self, registration, os_info, hostname, *, re_enroll=False):
        if self.state.data["credential"] and not re_enroll:
            raise ContractError("existing credential is preserved; explicit re-enrollment is required")
        if self.state.data["active"] or any(row["ack"] is None for row in self.state.data["outbox"].values()):
            raise ContractError("pending old identity must be reconciled before enrollment")
        if (registration.get("schema_version") != "2.0" or registration.get("family") != "WINDOWS"
                or registration.get("enrollment_header") != "X-Enrollment-Token"
                or normalize_url(registration.get("central_server_url", "")) != self.transport.base_url):
            raise ContractError("registration binding is invalid")
        if timestamp(registration.get("expires_at")) <= datetime.now(timezone.utc):
            raise ContractError("registration has expired")
        payload = {**envelope(), "enrollment_id": text(registration.get("enrollment_id")),
                   "hostname": text(hostname), "agent_version": AGENT_VERSION,
                   "os": os_info, "capabilities": ["CHECK"]}
        if os_info.get("family") != "WINDOWS": raise ContractError("Windows enrollment is required")
        response = self._retry_send("/enrollments", payload,
                                    enrollment_token=text(registration.get("token")), retryable=False)
        if response.status != 201: raise ContractError("enrollment did not return 201")
        credential = self._credential_response(response.body, server_id=text(registration.get("server_id")))
        with self.state.lock:
            previous = deepcopy(self.state.data)
            self.state.data["credential"] = credential
            self.state.data["rotation"] = None
            self.state.data["enrollment_receipt"] = {
                "enrollment_id": text(registration.get("enrollment_id")),
                "server_id": credential["server_id"], "central_server_url": self.transport.base_url}
            try:
                self.state.save()
            except Exception:
                self.state.data = previous
                raise
        return {key: val for key, val in credential.items() if key != "token"}

    def heartbeat(self):
        active = self.state.data.get("active")
        pending = sum(row["ack"] is None and row["path"].endswith("/results")
                      for row in self.state.data["outbox"].values())
        payload = {**self._envelope(), "agent_version": AGENT_VERSION, "module_version": self.manifest.version,
                   "health": "BUSY" if active else "READY", "active_job_id": active["task"]["job_id"] if active else None,
                   "pending_result_count": pending, "inventory_version": self.state.data.get("inventory_version")}
        key = "heartbeat:" + payload["message_id"]
        if not self.state.data.get("rotation"):
            awaiting = [name for name, row in self.state.data["outbox"].items()
                        if name.startswith("heartbeat:") and row["ack"] is None]
            if awaiting: key = awaiting[0]
        def validate(response, request):
            if response.status != 200: raise ContractError("invalid heartbeat status")
            ack = response.body
            timestamp(ack.get("received_at"))
            interval = ack.get("poll_after_sec")
            if type(interval) not in (int, float) or not 1 <= interval <= 3600:
                raise ContractError("invalid heartbeat interval")
            self.heartbeat_interval = min(float(interval), 30.0)
            return ack
        record = self._prepare(key, "/heartbeat", payload)
        ack = self._deliver(record, validate)
        with self.state.lock:
            self.state.data["outbox"].pop(key)
            pending_rotation = self.state.data.get("rotation")
            if pending_rotation and self.credential["credential_id"] == pending_rotation["new"]["credential_id"]:
                self.state.data["rotation"] = None
            self.state.save()
        return ack

    def send_inventory(self):
        snapshot = self.inventory(self.manifest, AGENT_VERSION)
        # 시각/UUID 대신 Central CC-03 계산 결과를 inventory version으로 사용한다.
        payload = {**self._envelope(), **snapshot}
        key = "inventory:" + hashlib.sha256(canonical(snapshot)).hexdigest()
        def validate(response, request):
            if response.status != 200: raise ContractError("invalid inventory status")
            ack = response.body
            text(ack.get("inventory_version"))
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", ack["inventory_version"]):
                raise ContractError("CC-03 deterministic inventory version is missing")
            timestamp(ack.get("received_at"))
            if type(ack.get("duplicate")) is not bool: raise ContractError("inventory duplicate flag missing")
            return ack
        record = self._prepare(key, "/inventory", payload)
        ack = self._deliver(record, validate)
        with self.state.lock:
            self.state.data["inventory_version"] = ack["inventory_version"]
            self.state.data["os"] = snapshot["os"]
            self.state.data["os_collection_status"] = snapshot["collection"]["os"]["status"]
            self.state.save()
        return ack

    def rotate(self):
        if self.state.data["active"]: raise ContractError("rotation requires an idle worker")
        if self.state.data.get("rotation"): raise ContractError("pending rotation requires explicit recovery")
        old = deepcopy(self.credential)
        payload = {**self._envelope(), "credential_id": old["credential_id"]}
        # rotate 응답 유실 시 토큰을 재회수하려고 재송신하지 않는다. old를 보존한다.
        response = self._retry_send("/credentials/rotate", payload, token=old["token"], retryable=False)
        if response.status != 201: raise ContractError("invalid rotation status")
        body = response.body
        if (body.get("confirmation") != "FIRST_SUCCESSFUL_AGENT_REQUEST"
                or body.get("old_credential_id") != old["credential_id"]):
            raise ContractError("rotation binding mismatch")
        timestamp(body.get("grace_until"))
        if timestamp(body["grace_until"]) > timestamp(old["expires_at"]):
            raise ContractError("rotation grace exceeds old expiry")
        text(body.get("rotation_id"))
        new = self._credential_response({**body, "server_id": old["server_id"], "agent_id": old["agent_id"]})
        if new["credential_id"] == old["credential_id"]: raise ContractError("rotation returned the old credential")
        with self.state.lock:
            previous_rotation = self.state.data.get("rotation")
            self.state.data["rotation"] = {"old": old, "new": new, "rotation_id": body["rotation_id"],
                                           "grace_until": body["grace_until"]}
            self.state.data["credential"] = new
            try:
                self.state.save()  # 새 token을 사용하기 전에 영구 보호 저장을 완료한다.
            except Exception:
                self.state.data["credential"] = old
                self.state.data["rotation"] = previous_rotation
                raise
        self.heartbeat()  # new 운영 요청의 성공 commit이 Central에서 old 폐기를 확정한다.
        with self.state.lock:
            self.state.data["rotation"] = None
            self.state.save()
        return {"credential_id": new["credential_id"], "confirmed": True}

    def recover_rotation(self):
        pending = self.state.data.get("rotation")
        if not pending or self.state.data["active"]:
            raise ContractError("no idle pending rotation to recover")
        new = deepcopy(self.credential)
        # 명시적 복구에서만 old 사용. 이미 new 확인으로 폐기된 old는 Central이 401로 거부한다.
        self.state.data["credential"] = pending["old"]
        try:
            ack = self.heartbeat()
        except Exception:
            self.state.data["credential"] = new
            raise
        if timestamp(ack["received_at"]) < timestamp(pending["grace_until"]):
            return {"recovered": False, "pending": True}
        with self.state.lock:
            self.state.data["rotation"] = None
            self.state.save()
        return {"recovered": True}

    def _event(self, active, event, processed, *, deadline=True):
        task = active["task"]
        path = "/tasks/" + quote(task["job_id"], safe="") + "/events"
        key = f"{task['attempt_id']}:event:{event}"
        if event in {"LEASE_RENEWAL", "PROGRESS"}: key += ":" + str(uuid.uuid4())
        payload = {**self._envelope(), "attempt_id": task["attempt_id"], "event": event,
                   "processed_item_count": processed, "requested_lease_until": None,
                   "error": {"code": "AGENT_WORKFLOW_FAILED", "message": "CHECK workflow could not complete"}
                   if event == "FAILED" else None}
        def validate(response, request):
            if response.status != 200 or response.body.get("accepted_message_id") != request["message_id"]:
                raise ContractError("event ACK does not match this message")
            timestamp(response.body.get("received_at"))
            return response.body
        started = self.clock()
        ack = self._deliver(self._prepare(key, path, payload), validate,
                            deadline=self.lease.deadline if deadline else None, replay=True)
        if timestamp(ack.get("lease_until")) > timestamp(task["expires_at"]):
            raise ContractError("event lease exceeds job expiry")
        self.lease.update(ack, started)
        return ack

    def _claim(self):
        active = self.state.data.get("active")
        pending = [key for key, record in self.state.data["outbox"].items()
                   if key.startswith("claim:") and record["ack"] is None]
        if len(pending) > 1: raise ContractError("ambiguous pending claim requires reconciliation")
        key = active["claim_key"] if active else pending[0] if pending else "claim:" + str(uuid.uuid4())
        payload = {**self._envelope(), "capabilities": ["CHECK"],
                   "agent_version": AGENT_VERSION, "module_version": self.manifest.version}
        def validate(response, request):
            if response.status == 204: return None
            if response.status != 200: raise ContractError("invalid claim status")
            validate_task(response.body, self.credential, self.manifest)
            return response.body
        record = self._prepare(key, "/tasks/claim", payload)
        started = self.clock()
        try:
            task = self._deliver(record, validate, replay=True)
        except CentralError as exc:
            if exc.status != 409 or exc.code != "ATTEMPT_STALE":
                raise
            with self.state.lock:
                # 이전 attempt의 미확인 원본은 격리 보존한다. 새 attempt로 ID만 바꿔 제출하지 않는다.
                keys = [name for name in self.state.data["outbox"] if name == key or
                        (active and name.startswith(active["task"]["attempt_id"] + ":"))]
                archive = {name: self.state.data["outbox"].pop(name) for name in keys}
                self.state.data.setdefault("reconciliation", []).append({"active": deepcopy(active), "records": archive})
                self.state.data["active"] = None
                self.state.save()
            # 다음 poll에서만 새 logical claim을 생성한다.
            return None
        if task is None:
            if active: raise ContractError("active attempt was not revalidated")
            with self.state.lock:
                self.state.data["outbox"].pop(key)
                self.state.save()
            return None
        self.lease.update(task, started)
        self.lease.require()
        if active:
            if (active["task"]["attempt_id"] != task["attempt_id"]
                    or active["task"]["job_id"] != task["job_id"]):
                raise ContractError("attempt changed; pending records require reconciliation")
            active["task"] = task
        else:
            active = {"task": task, "claim_key": key, "items": {}}
            self.state.data["active"] = active
        self.state.save()
        return active

    def _item(self, active, code):
        task = active["task"]
        rows = active["items"]
        if code in rows and rows[code].get("collecting"):
            raise ContractError("collector was interrupted; do not silently re-execute")
        if code not in rows:
            self.lease.require()
            rows[code] = {"collecting": True}
            self.state.save()
            try:
                observation = self.checker(code)
            except Exception:
                observation = _result(code, "UNABLE", "WINDOWS_API_UNAVAILABLE", {},
                                      manual_review_required=True, error_reason="Collector execution failed")
            self.lease.require()
            if observation.item_id != code or observation.status not in {"PASS", "FAIL", "NA", "UNABLE"}:
                raise ContractError("invalid local CHECK result")
            timestamp(observation.observed_at)
            current = safe_observation(observation.current_value, self._tokens())
            current["manual_review_required"] = bool(observation.manual_review_required)
            # 수동 판단은 UNABLE/COMPLETED를 유지한다. 실제 수집 예외만 FAILED로 구분한다.
            failed = observation.reason_code in {"WINDOWS_API_UNAVAILABLE", "COLLECTOR_ERROR"}
            if failed and observation.status != "UNABLE": raise ContractError("collector failure cannot be PASS")
            if observation.error_reason:
                current["diagnostic_reason"] = safe_observation(observation.error_reason, self._tokens())
            evidence = {"item_id": code, "current_value": current, "source_page": observation.source_page,
                        "observed_at": observation.observed_at, "reason_code": text(observation.reason_code)}
            file_bytes = canonical(evidence)
            if len(file_bytes) > 1024 * 1024: raise ContractError("evidence exceeds 1 MiB")
            evidence_id = str(uuid.uuid4())
            metadata = {**self._envelope(), "evidence_id": evidence_id, "server_id": task["server_id"],
                        "scan_run_id": task["scan_run_id"], "attempt_id": task["attempt_id"], "item_id": code,
                        "collector_id": f"{code}.collect.{self.manifest.version}", "captured_at": observation.observed_at,
                        "redacted": True, "media_type": "application/json", "sha256": hashlib.sha256(file_bytes).hexdigest(),
                        "byte_length": len(file_bytes)}
            result = {**self._envelope(), **{key: task[key] for key in
                        ("server_id", "job_id", "scan_run_id", "attempt_id", "criteria_snapshot_id")},
                      "result_id": str(uuid.uuid4()), "item_id": code, "status": observation.status,
                      "review_state": "NOT_REQUIRED", "auto_stage_state": "FAILED" if failed else "COMPLETED",
                      "reason_code": observation.reason_code, "observed_at": observation.observed_at,
                      "evidence_ids": [evidence_id], "current_value": current,
                      "error": {"code": "COLLECTION_FAILED", "message": "Windows collection failed"} if failed else None}
            prefix = task["attempt_id"] + ":" + code
            # 수집 결과와 두 논리 요청을 한 저장 단위로 영속화한다.
            with self.state.lock:
                self._prepare(prefix + ":evidence", "/evidence-uploads", metadata, file_bytes, save=False)
                self._prepare(prefix + ":result", "/tasks/" + quote(task["job_id"], safe="") + "/results", result, save=False)
                rows[code] = {"collecting": False, "evidence_key": prefix + ":evidence", "result_key": prefix + ":result"}
                self.state.save()
        row = rows[code]
        def evidence_ack(response, request):
            if (response.status != 201 or any(response.body.get(key) != request[key] for key in
                    ("evidence_id", "sha256", "byte_length"))): raise ContractError("evidence ACK mismatch")
            return response.body
        self._deliver(self.state.data["outbox"][row["evidence_key"]], evidence_ack, deadline=self.lease.deadline)
        def result_ack(response, request):
            if response.status != 200: raise ContractError("invalid result ACK status")
            accepted, duplicate = response.body.get("accepted_ids"), response.body.get("duplicate_ids")
            if not isinstance(accepted, list) or not isinstance(duplicate, list) or request["result_id"] not in accepted+duplicate:
                raise ContractError("result ID missing from ACK")
            timestamp(response.body.get("received_at"))
            return response.body
        self._deliver(self.state.data["outbox"][row["result_key"]], result_ack, deadline=self.lease.deadline)

    def poll_once(self):
        if not self.operation_lock.acquire(blocking=False): raise ContractError("one worker is already active")
        stop = threading.Event()
        monitor = None
        active = None
        self.background_error = None
        try:
            previous = self.state.data.get("active")
            if previous:
                terminal_key = previous["task"]["attempt_id"] + ":event:COMPLETED"
                terminal = self.state.data["outbox"].get(terminal_key)
                if terminal:
                    ack = self._event(previous, "COMPLETED", len(previous["task"]["item_ids"]), deadline=False)
                    self._finish(previous)
                    return {"claimed": True, "job_id": previous["task"]["job_id"], "completed": True, "ack": ack}
            os_info = self.state.data.get("os", {})
            if self.state.data.get("os_collection_status") != "SUCCEEDED" or not self.manifest.supports(os_info):
                raise ContractError("actual OS is not covered by approved manifest or collection failed")
            active = self._claim()
            if active is None: return {"claimed": False}
            task = active["task"]
            remaining = validate_task(task, self.credential, self.manifest)
            self._event(active, "STARTED", len(task["completed_item_ids"]))
            def maintain():
                next_heartbeat = self.clock() + self.heartbeat_interval
                while not stop.wait(0.1):
                    try:
                        self.lease.require()
                        if self.clock() >= next_heartbeat:
                            self.heartbeat()
                            next_heartbeat = self.clock() + self.heartbeat_interval
                        if self.lease.deadline-self.clock() <= task["lease_duration_sec"] * self.renewal_fraction:
                            self._event(active, "LEASE_RENEWAL", self._processed(active))
                    except Exception as exc:
                        self.background_error = exc
                        return
            monitor = threading.Thread(target=maintain, daemon=True)
            monitor.start()
            for code in remaining:
                if self.background_error: raise self.background_error
                self.lease.require()
                self._item(active, code)
            stop.set()
            monitor.join()
            if self.background_error: raise self.background_error
            self.lease.require()
            ack = self._event(active, "COMPLETED", len(task["item_ids"]))
            self._finish(active)
            return {"claimed": True, "job_id": task["job_id"], "completed": True, "ack": ack}
        except ContractError:
            stop.set()
            if monitor is not None: monitor.join(timeout=15)
            if active is not None and self.clock() < self.lease.deadline:
                try:
                    self._event(active, "FAILED", len(active["task"]["completed_item_ids"]))
                except Exception:
                    pass
            raise
        finally:
            stop.set()
            if monitor is not None: monitor.join(timeout=15)
            self.operation_lock.release()

    def _finish(self, active):
        with self.state.lock:
            self.state.data["active"] = None
            prefix = active["task"]["attempt_id"] + ":"
            for key in [key for key in self.state.data["outbox"] if key == active["claim_key"] or key.startswith(prefix)]:
                self.state.data["outbox"].pop(key)
            self.state.save()

    def _processed(self, active):
        codes = set(active["task"]["completed_item_ids"])
        codes.update(code for code, row in active["items"].items() if not row.get("collecting")
                     and self.state.data["outbox"][row["result_key"]]["ack"] is not None)
        return len(codes)

    def run(self, stop):
        self.heartbeat()
        self.send_inventory()
        next_hb = self.clock()+self.heartbeat_interval
        while not stop.is_set():
            if self.clock() >= next_hb:
                self.heartbeat()
                next_hb = self.clock()+self.heartbeat_interval
            self.poll_once()
            stop.wait(min(self.poll_interval, max(0.1, next_hb-self.clock())))
