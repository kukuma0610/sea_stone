"""Central 계약의 합성 HTTP 테스트. 실제 Windows 변경·Central 연결은 하지 않는다."""

from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent.checks import CHECK_REGISTRY
from agent.checks.common import _result
from agent.central.contract import (ContractError, Manifest, Lease, canonical, safe_observation,
                                    validate_task)
from agent.central.storage import ProtectedState, StorageError, DPAPI, restrict_acl
from agent.central.transport import CentralError, CentralTransport, Response, NoRedirect, normalize_url, require_installed_ca
from agent.central.service import CentralAgent
from agent.central.inventory import collect_snapshot


OS = {"family": "WINDOWS", "version": "10.0.20348", "build": "20348", "architecture": "AMD64"}


def manifest_data():
    return {"schema_version": "1.0", "manifest_id": "test-approved-manifest", "module_version": "test-release",
            "platform": "windows", "supported_os": [OS], "items": [
                {"item_id": code, "module": f"agent.checks.w{code[2:]}", "implemented": True, "actions": ["CHECK"]}
                for code in CHECK_REGISTRY]}


class TestProtector:
    def protect(self, raw): return bytes(byte ^ 0xA7 for byte in raw)
    def unprotect(self, raw): return self.protect(raw)


class FakeCentral:
    base_url = "https://central.example/agent-api/v2"

    def __init__(self):
        self.calls = []
        self.records = {}
        self.no_task = False
        self.completed = ["W-02"]
        self.fail_result_once = False
        self.rotation_lost = False
        self.before_new_request = None
        self.old_revoked = False

    @staticmethod
    def now(): return datetime.now(timezone.utc).isoformat()

    def timing(self):
        now = datetime.now(timezone.utc)
        return {"server_time": now.isoformat(), "lease_until": (now+timedelta(seconds=120)).isoformat(), "lease_duration_sec": 120.0}

    def task(self):
        return {"schema_version": "2.0", "job_id": "job", "scan_run_id": "run", "server_id": "server",
                "agent_id": "agent", "attempt_id": "attempt", "action": "CHECK", "scan_scope": "PARTIAL",
                "item_ids": ["W-02", "W-04"], "planned_item_count": 2, "completed_item_ids": self.completed,
                "manifest_id": "test-approved-manifest", "module_version": "test-release", "criteria_snapshot_id": "criteria",
                "expires_at": (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
                "authorization": {"grant_id": None, "approval_id": None}, "simulation": False,
                "settings": {}, "backup_id": None, "execution_phase": "CHECK", **self.timing()}

    def send(self, path, payload, headers, file_bytes=None):
        self.calls.append((path, deepcopy(payload), deepcopy(headers), file_bytes))
        if headers.get("Authorization") == "Bearer new-secret":
            if self.before_new_request: self.before_new_request()
            self.old_revoked = True
        message = payload["message_id"]
        data = canonical(payload)
        if message in self.records and self.records[message] != (path, data, file_bytes):
            raise CentralError("IDEMPOTENCY_CONFLICT", 409)
        duplicate = message in self.records
        self.records[message] = (path, data, file_bytes)
        if path == "/enrollments":
            return Response(201, {"server_id": "server", "agent_id": "agent", "credential_id": "old-id",
                                  "token": "old-secret", "expires_at": "2099-01-01T00:00:00Z"})
        if path == "/credentials/rotate":
            if self.rotation_lost: raise CentralError("NETWORK_ERROR")
            return Response(201, {"credential_id": "new-id", "token": "new-secret", "expires_at": "2099-01-01T00:00:00Z",
                                  "rotation_id": "rotation", "old_credential_id": "old-id",
                                  "grace_until": "2098-01-01T00:00:00Z", "confirmation": "FIRST_SUCCESSFUL_AGENT_REQUEST"})
        if path == "/heartbeat": return Response(200, {"received_at": self.now(), "poll_after_sec": 30})
        if path == "/inventory":
            return Response(200, {"inventory_version": "sha256:"+hashlib.sha256(data).hexdigest(),
                                  "received_at": self.now(), "duplicate": duplicate})
        if path == "/tasks/claim": return Response(204, None) if self.no_task else Response(200, self.task())
        if path == "/evidence-uploads":
            assert len(file_bytes) == payload["byte_length"]
            assert hashlib.sha256(file_bytes).hexdigest() == payload["sha256"]
            return Response(201, {"evidence_id": payload["evidence_id"], "sha256": payload["sha256"],
                                  "byte_length": len(file_bytes), "received_at": self.now()})
        if path.endswith("/results"):
            if self.fail_result_once:
                self.fail_result_once = False
                raise CentralError("NETWORK_ERROR")
            return Response(200, {"accepted_ids": [] if duplicate else [payload["result_id"]],
                                  "duplicate_ids": [payload["result_id"]] if duplicate else [], "received_at": self.now()})
        if path.endswith("/events"):
            return Response(200, {"accepted_message_id": message, "received_at": self.now(), **self.timing()})
        raise AssertionError(path)


class CentralTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.protector = TestProtector()
        self.state = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        self.manifest = Manifest(manifest_data())
        self.central = FakeCentral()
        self.executed = []
        def checker(code):
            self.executed.append(code)
            return _result(code, "PASS", "TEST_KISA_CRITERIA", {"password_protected": False})
        def inventory(manifest, agent_version):
            return {"hostname": "test-host", "platform": "windows", "os": OS, "agent_version": agent_version,
                    "module_version": manifest.version, "manifest_id": manifest.id, "roles": [], "services": [],
                    "collection": {name: {"status": "SUCCEEDED", "error": None} for name in ("os", "roles", "services")}}
        self.agent = CentralAgent(self.central, self.state, self.manifest, checker=checker, inventory=inventory,
                                  retry_base=0, sleep=lambda duration: None)
        self.registration = {"schema_version": "2.0", "family": "WINDOWS", "enrollment_header": "X-Enrollment-Token",
                             "enrollment_id": "issued-enrollment", "token": "enrollment-secret", "server_id": "server",
                             "expires_at": "2099-01-01T00:00:00Z", "central_server_url": self.central.base_url}

    def enroll(self): self.agent.enroll(self.registration, OS, "test-host")

    def start(self):
        self.enroll()
        self.agent.heartbeat()
        self.agent.send_inventory()

    def test_enrollment_and_central_identity_are_protected(self):
        self.enroll()
        call = self.central.calls[0]
        self.assertEqual(call[2], {"X-Enrollment-Token": "enrollment-secret"})
        self.assertEqual(call[1]["enrollment_id"], "issued-enrollment")
        self.assertEqual(len(call[1]), 8)
        self.assertNotIn("agent_id", call[1])
        self.agent.heartbeat()
        self.assertEqual(self.central.calls[-1][1]["agent_id"], "agent")
        self.assertNotIn(b"old-secret", self.state.path.read_bytes())
        restored = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        self.assertEqual(restored.data["credential"]["agent_id"], "agent")

    def test_existing_credential_is_not_silently_replaced(self):
        self.enroll()
        with self.assertRaises(ContractError): self.enroll()
        self.assertEqual(len(self.central.calls), 1)

    def test_rotation_is_saved_before_first_new_request(self):
        self.enroll()
        def before_request():
            disk = json.loads(self.protector.unprotect(self.state.path.read_bytes()))
            self.assertEqual(disk["credential"]["token"], "new-secret")
            self.assertEqual(disk["rotation"]["old"]["token"], "old-secret")
        self.central.before_new_request = before_request
        self.agent.rotate()
        self.assertTrue(self.central.old_revoked)
        self.assertIsNone(self.state.data["rotation"])

    def test_rotation_response_loss_keeps_old_without_retry(self):
        self.enroll()
        self.central.rotation_lost = True
        with self.assertRaises(CentralError): self.agent.rotate()
        self.assertEqual(self.state.data["credential"]["token"], "old-secret")
        self.assertFalse(self.central.old_revoked)
        self.assertEqual(sum(path == "/credentials/rotate" for path, *_ in self.central.calls), 1)

    def test_rotation_storage_failure_never_uses_new_token(self):
        self.enroll()
        with patch.object(self.state, "save", side_effect=OSError):
            with self.assertRaises(OSError): self.agent.rotate()
        self.assertEqual(self.state.data["credential"]["token"], "old-secret")
        self.assertFalse(self.central.old_revoked)

    def test_actual_partial_evidence_result_completion_flow(self):
        self.start()
        result = self.agent.poll_once()
        self.assertTrue(result["completed"])
        self.assertEqual(self.executed, ["W-04"])
        calls = [path for path, *_ in self.central.calls]
        self.assertLess(calls.index("/evidence-uploads"), calls.index("/tasks/job/results"))
        payload = next(body for path, body, *_ in self.central.calls if path.endswith("/results"))
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["review_state"], "NOT_REQUIRED")
        self.assertEqual(payload["auto_stage_state"], "COMPLETED")
        self.assertIs(payload["current_value"]["password_protected"], False)
        self.assertIsNone(self.state.data["active"])

    def test_retry_reuses_entire_result_payload(self):
        self.start()
        self.central.fail_result_once = True
        self.agent.poll_once()
        requests = [body for path, body, *_ in self.central.calls if path.endswith("/results")]
        self.assertEqual(len(requests), 2)
        self.assertEqual(canonical(requests[0]), canonical(requests[1]))
        self.assertEqual(self.executed, ["W-04"])

    def test_204_is_normal_and_next_poll_has_new_message(self):
        self.start()
        self.central.no_task = True
        self.assertFalse(self.agent.poll_once()["claimed"])
        self.assertFalse(self.agent.poll_once()["claimed"])
        requests = [body for path, body, *_ in self.central.calls if path == "/tasks/claim"]
        self.assertNotEqual(requests[0]["message_id"], requests[1]["message_id"])
        self.assertFalse(self.executed)

    def test_result_ack_missing_id_is_not_completed(self):
        self.start()
        original = self.central.send
        def bad(path, payload, headers, file_bytes=None):
            response = original(path, payload, headers, file_bytes)
            if path.endswith("/results"): return Response(200, {"accepted_ids": [], "duplicate_ids": [], "received_at": self.central.now()})
            return response
        self.central.send = bad
        with self.assertRaises(ContractError): self.agent.poll_once()
        self.assertFalse(any(body.get("event") == "COMPLETED" for path, body, *_ in self.central.calls))

    def test_manual_unable_is_not_forced_to_null_pending(self):
        self.start()
        self.agent.checker = lambda code: _result(code, "UNABLE", "MANUAL_REVIEW", {}, manual_review_required=True)
        self.agent.poll_once()
        payload = next(body for path, body, *_ in self.central.calls if path.endswith("/results"))
        self.assertEqual((payload["status"], payload["review_state"], payload["auto_stage_state"]),
                         ("UNABLE", "NOT_REQUIRED", "COMPLETED"))

    def test_collector_error_is_unable_failed_and_sanitized(self):
        self.start()
        def failed(code): raise OSError("token=old-secret")
        self.agent.checker = failed
        self.agent.poll_once()
        payload = next(body for path, body, *_ in self.central.calls if path.endswith("/results"))
        self.assertEqual((payload["status"], payload["auto_stage_state"]), ("UNABLE", "FAILED"))
        self.assertNotIn("old-secret", json.dumps(payload))

    def test_forbidden_scope_binding_and_versions(self):
        self.enroll()
        for change in ({"item_ids": ["W-99"], "planned_item_count": 1},
                       {"item_ids": ["W-04", "W-04"]}, {"completed_item_ids": ["W-05"]},
                       {"agent_id": "other"}, {"simulation": True}, {"module_version": "other"},
                       {"settings": {"nested": {"PoWeR_Shell": "anything"}}}, {"scan_scope": "FULL"}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                validate_task({**self.central.task(), **change}, self.agent.credential, self.manifest)

    def test_manifest_mock_version_or_unknown_module_is_rejected(self):
        value = manifest_data()
        value["module_version"] = "windows-agent-mock-0.1.0"
        with self.assertRaises(ContractError): Manifest(value)
        value = manifest_data()
        value["items"][0]["module"] = "remote.module"
        with self.assertRaises(ContractError): Manifest(value)

    def test_lease_uses_monotonic_and_subtracts_roundtrip(self):
        clock = [100.0]
        lease = Lease(lambda: clock[0])
        response = self.central.timing()
        clock[0] = 104.0
        lease.update(response, 100.0)
        self.assertEqual(lease.deadline, 220.0)
        clock[0] = 220.0
        with self.assertRaises(ContractError): lease.require()

    def test_inventory_failure_and_empty_success_are_distinct(self):
        class Api:
            def windows_os_info(self): return {"caption": "Windows Server 2022", "version": "10.0.20348", "build_number": "20348"}
            def _run_powershell_json(self, script): return [{"roles": []}]
            def running_services(self): return []
        first = collect_snapshot(self.manifest, "0.1.0", Api())
        self.assertEqual(first["collection"]["services"]["status"], "SUCCEEDED")
        with patch.object(Api, "running_services", side_effect=OSError("secret")):
            second = collect_snapshot(self.manifest, "0.1.0", Api())
        self.assertEqual(second["services"], [])
        self.assertEqual(second["collection"]["services"]["status"], "FAILED")
        self.assertNotEqual(canonical(first), canonical(second))

    def test_safe_boolean_and_real_secret_redaction(self):
        value = {"password_protected": False, "password_policy_enabled": True, "password": "secret",
                 "nested": {"password_protected": {"state": "present", "value": False, "error_reason": None}},
                 "other": "Bearer old-secret"}
        result = safe_observation(value, ["old-secret"])
        self.assertIs(result["password_protected"], False)
        self.assertEqual(result["password"], "[REDACTED]")
        self.assertIs(result["nested"]["password_protected"]["value"], False)
        self.assertEqual(result["other"], "[REDACTED]")

    def test_auth_tls_and_conflict_errors_do_not_retry(self):
        self.enroll()
        for error in (CentralError("CREDENTIAL_INVALID", 401), CentralError("IDEMPOTENCY_CONFLICT", 409),
                      CentralError("TLS_VALIDATION_FAILED")):
            with patch.object(self.central, "send", side_effect=error) as send:
                with self.assertRaises(CentralError): self.agent.heartbeat()
                self.assertEqual(send.call_count, 1)

    def test_redirect_and_prefix_normalization(self):
        self.assertEqual(normalize_url("https://central.example"), self.central.base_url)
        self.assertEqual(normalize_url(self.central.base_url), self.central.base_url)
        for url in ("http://central.example", "https://u:p@central.example", self.central.base_url+"/agent-api/v2"):
            with self.assertRaises(ContractError): normalize_url(url)
        with self.assertRaises(CentralError): NoRedirect().redirect_request(None, None, 302, "", {}, "https://other")

    def test_pending_claim_uses_same_message_after_restart(self):
        self.start()
        original = self.central.send
        failed = [True]
        def send(path, payload, headers, file_bytes=None):
            if path == "/tasks/claim" and failed[0]:
                failed[0] = False
                original(path, payload, headers, file_bytes)
                raise CentralError("NETWORK_ERROR")
            return original(path, payload, headers, file_bytes)
        self.central.send = send
        self.agent.retries = 0
        with self.assertRaises(CentralError): self.agent.poll_once()
        restored = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        next_agent = CentralAgent(self.central, restored, self.manifest, checker=self.agent.checker,
                                 inventory=self.agent.inventory, retry_base=0)
        next_agent.poll_once()
        requests = [body for path, body, *_ in self.central.calls if path == "/tasks/claim"]
        self.assertEqual(canonical(requests[0]), canonical(requests[1]))

    def test_reparse_state_is_rejected(self):
        with patch("agent.central.storage.reject_reparse", side_effect=StorageError):
            with self.assertRaises(StorageError): ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)

    def test_result_response_loss_survives_restart_without_reexecution(self):
        self.start()
        self.central.fail_result_once = True
        self.agent.retries = 0
        with self.assertRaises(CentralError): self.agent.poll_once()
        original_requests = [body for path, body, *_ in self.central.calls if path.endswith("/results")]
        restored = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        agent = CentralAgent(self.central, restored, self.manifest, checker=self.agent.checker, retry_base=0)
        agent.poll_once()
        requests = [body for path, body, *_ in self.central.calls if path.endswith("/results")]
        self.assertEqual(canonical(original_requests[0]), canonical(requests[-1]))
        self.assertEqual(self.executed, ["W-04"])

    def test_completion_loss_replays_terminal_message_without_claim_or_collect(self):
        self.start()
        original = self.central.send
        lost = [True]
        def send(path, payload, headers, file_bytes=None):
            response = original(path, payload, headers, file_bytes)
            if payload.get("event") == "COMPLETED" and lost[0]:
                lost[0] = False
                raise CentralError("NETWORK_ERROR")
            return response
        self.central.send = send
        self.agent.retries = 0
        with self.assertRaises(CentralError): self.agent.poll_once()
        claim_count = sum(path == "/tasks/claim" for path, *_ in self.central.calls)
        restored = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        agent = CentralAgent(self.central, restored, self.manifest, checker=self.agent.checker, retry_base=0)
        agent.poll_once()
        self.assertEqual(sum(path == "/tasks/claim" for path, *_ in self.central.calls), claim_count)
        self.assertEqual(self.executed, ["W-04"])
        completed = [body for path, body, *_ in self.central.calls if body.get("event") == "COMPLETED"]
        self.assertEqual(canonical(completed[0]), canonical(completed[1]))

    def test_stale_attempt_is_quarantined_and_next_poll_uses_fresh_claim(self):
        self.start()
        self.central.fail_result_once = True
        self.agent.retries = 0
        with self.assertRaises(CentralError): self.agent.poll_once()
        original = self.central.send
        stale = [True]
        def send(path, payload, headers, file_bytes=None):
            if path == "/tasks/claim" and stale[0]:
                stale[0] = False
                raise CentralError("ATTEMPT_STALE", 409)
            return original(path, payload, headers, file_bytes)
        self.central.send = send
        self.assertFalse(self.agent.poll_once()["claimed"])
        self.assertIsNone(self.state.data["active"])
        self.assertTrue(self.state.data["reconciliation"])

    def test_lease_expiry_during_collector_blocks_result_submission(self):
        self.start()
        def expired(code):
            self.agent.lease.deadline = self.agent.clock()-1
            return _result(code, "PASS", "TEST", {})
        self.agent.checker = expired
        with self.assertRaises(ContractError): self.agent.poll_once()
        self.assertFalse(any(path.endswith("/results") for path, *_ in self.central.calls))

    def test_full_plan_calls_all_existing_collectors(self):
        self.start()
        original = self.central.task
        def full():
            task = original()
            task.update(scan_scope="FULL", item_ids=list(CHECK_REGISTRY), completed_item_ids=[], planned_item_count=64)
            return task
        self.central.task = full
        self.agent.poll_once()
        self.assertEqual(self.executed, list(CHECK_REGISTRY))

    def test_heartbeat_response_loss_replays_same_payload_after_restart(self):
        self.enroll()
        original = self.central.send
        lost = [True]
        def send(path, payload, headers, file_bytes=None):
            response = original(path, payload, headers, file_bytes)
            if path == "/heartbeat" and lost[0]:
                lost[0] = False
                raise CentralError("NETWORK_ERROR")
            return response
        self.central.send = send
        self.agent.retries = 0
        with self.assertRaises(CentralError): self.agent.heartbeat()
        restored = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        agent = CentralAgent(self.central, restored, self.manifest)
        agent.heartbeat()
        requests = [body for path, body, *_ in self.central.calls if path == "/heartbeat"]
        self.assertEqual(canonical(requests[0]), canonical(requests[1]))

    def test_transport_handles_204_without_decoding_json(self):
        transport = CentralTransport(self.central.base_url)
        with patch.object(transport.opener, "open") as opened:
            response = opened.return_value.__enter__.return_value
            response.status = 204
            response.read.return_value = b""
            self.assertIsNone(transport.send("/tasks/claim", {"message_id": "id"}, {}).body)
            response.read.return_value = b"unexpected"
            with self.assertRaises(ContractError): transport.send("/tasks/claim", {"message_id": "id"}, {})

    def test_dpapi_is_current_user_noninteractive_and_frees_buffer(self):
        import ctypes
        from unittest.mock import MagicMock
        crypt, kernel = MagicMock(), MagicMock()
        buffers = []
        def transform(incoming, description, entropy, reserved, prompt, flags, outgoing):
            self.assertEqual(flags, 1)  # UI_FORBIDDEN만 사용, LOCAL_MACHINE 없음
            self.assertIsNone(prompt)
            buffer = ctypes.create_string_buffer(b"fake-protected")
            buffers.append(buffer)
            blob = ctypes.cast(outgoing, ctypes.POINTER(DPAPI.Blob)).contents
            blob.length = len(b"fake-protected")
            blob.data = ctypes.addressof(buffer)
            return True
        crypt.CryptProtectData.side_effect = transform
        with patch("agent.central.storage.ctypes.WinDLL", side_effect=lambda name, **kw: crypt if name == "crypt32" else kernel):
            self.assertEqual(DPAPI().protect(b"fake-secret"), b"fake-protected")
        kernel.LocalFree.assert_called_once()

    def test_protection_failure_does_not_write_plaintext(self):
        self.enroll()
        previous = self.state.path.read_bytes()
        with patch.object(self.protector, "protect", side_effect=StorageError):
            with self.assertRaises(StorageError): self.state.save()
        self.assertEqual(self.state.path.read_bytes(), previous)

    def test_retry_after_and_limits_are_bounded(self):
        self.enroll()
        self.agent.retries = 2
        sleeps = []
        self.agent.sleep = sleeps.append
        with patch.object(self.central, "send", side_effect=CentralError("RATE_LIMITED", 429, "2")) as send:
            with self.assertRaises(CentralError): self.agent.heartbeat()
        self.assertEqual(send.call_count, 3)
        self.assertEqual(sleeps, [2.0, 2.0])

    def test_rotation_confirmation_loss_restores_pending_new_on_restart(self):
        self.enroll()
        original = self.central.send
        lost = [True]
        def send(path, payload, headers, file_bytes=None):
            response = original(path, payload, headers, file_bytes)
            if headers.get("Authorization") == "Bearer new-secret" and lost[0]:
                lost[0] = False
                raise CentralError("NETWORK_ERROR")
            return response
        self.central.send = send
        self.agent.retries = 0
        with self.assertRaises(CentralError): self.agent.rotate()
        restored = ProtectedState(self.temp.name, protector=self.protector, acl=lambda path: None)
        self.assertEqual(restored.data["credential"]["token"], "new-secret")
        self.assertIsNotNone(restored.data["rotation"])
        agent = CentralAgent(self.central, restored, self.manifest)
        agent.heartbeat()
        self.assertIsNone(restored.data["rotation"])

    def test_wire_flow_reuses_actual_w02_w04_check_modules(self):
        from agent.windows_checks import collect_check
        self.start()
        self.central.completed = []
        class ReadOnlyApi:
            def accounts(self):
                return [{"user_id": 501, "name": "Guest", "disabled": True}]
            def lockout_threshold(self): return 6
        self.agent.checker = lambda code: collect_check(code, ReadOnlyApi())
        self.agent.poll_once()
        results = [body for path, body, *_ in self.central.calls if path.endswith("/results")]
        self.assertEqual([(row["item_id"], row["status"]) for row in results], [("W-02", "PASS"), ("W-04", "FAIL")])

    def test_public_ca_requires_verified_windows_root_trust(self):
        with patch("agent.central.transport.ssl.enum_certificates", return_value=[(b"approved-public-ca", "x509_asn", True)]):
            require_installed_ca(b"approved-public-ca")
            with self.assertRaises(ContractError): require_installed_ca(b"different-ca")
        with patch("agent.central.transport.ssl.enum_certificates", side_effect=OSError):
            with self.assertRaises(ContractError): require_installed_ca(b"approved-public-ca")
