"""등록/ONLINE 전용 CLI: 실제 OS 정책과 Central을 변경하지 않는 테스트."""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import io
import json
import unittest
from unittest.mock import patch

from agent.central import __main__ as cli
from agent.central.contract import ContractError
from agent.central.storage import ProtectedState
from agent.central.transport import CentralError
from tests.test_central import FakeCentral, TestProtector, OS


class RegistrationCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.central = FakeCentral()
        self.state = ProtectedState(self.root / "state", protector=TestProtector(), acl=lambda path: None)
        self.registration = {"schema_version": "2.0", "family": "WINDOWS", "enrollment_header": "X-Enrollment-Token",
                             "enrollment_id": "enrollment", "server_id": "server", "token": "enrollment-secret",
                             "central_server_url": self.central.base_url, "ca_sha256_fingerprint": "a" * 64,
                             "expires_at": "2099-01-01T00:00:00Z"}
        self.reg_path = self.root / "os-guard-registration.json"
        self.reg_path.write_text(json.dumps(self.registration), encoding="utf-8")
        self.config = {"central_server_url": self.central.base_url, "state_dir": "state", "ca_file": "public-ca.pem",
                       "ca_sha256_fingerprint": "a" * 64, "retry_count": 0}
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    @staticmethod
    def inventory(manifest, version):
        return {"hostname": "test-host", "platform": "windows", "os": OS, "agent_version": version,
                "module_version": manifest.version, "manifest_id": manifest.id, "roles": [], "services": [],
                "collection": {key: {"status": "SUCCEEDED", "error": None} for key in ("os", "roles", "services")}}

    def invoke(self, command="enroll", extra=()):
        from agent.central.service import CentralAgent
        args = [command, "--config", str(self.config_path), *extra]
        if command == "enroll": args += ["--registration-file", str(self.reg_path)]
        def agent(transport, state, manifest, **options):
            return CentralAgent(transport, state, manifest, inventory=self.inventory, checker=lambda code: self.fail("CHECK called"), **options)
        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, "CentralTransport", return_value=self.central))
            stack.enter_context(patch.object(cli, "ProtectedState", return_value=self.state))
            stack.enter_context(patch.object(cli, "CentralAgent", side_effect=agent))
            stack.enter_context(patch.object(cli, "collect_snapshot", side_effect=self.inventory))
            stack.enter_context(patch.object(cli, "restrict_acl"))
            output = stack.enter_context(redirect_stdout(io.StringIO()))
            result = cli.main(args)
        self.assertNotIn("enrollment-secret", output.getvalue())
        self.assertNotIn("old-secret", output.getvalue())
        return result

    def test_enroll_to_inventory_and_heartbeat_without_claim(self):
        self.assertEqual(self.invoke(), 0)
        self.assertFalse(self.reg_path.exists())
        self.assertEqual([call[0] for call in self.central.calls], ["/enrollments", "/heartbeat", "/inventory", "/heartbeat"])
        inventory = self.central.calls[2][1]
        self.assertEqual(inventory["platform"], "windows")
        self.assertEqual(inventory["module_version"], "windows-2026.1")
        self.assertEqual(inventory["manifest_id"], "manifest-windows-64-2026-v1")
        self.assertEqual(self.central.calls[-1][1]["inventory_version"], self.state.data["inventory_version"])
        self.assertNotIn(b"old-secret", self.state.path.read_bytes())

    def test_network_failure_preserves_registration(self):
        with patch.object(self.central, "send", side_effect=CentralError("NETWORK_ERROR")):
            self.assertEqual(self.invoke(), 1)
        self.assertTrue(self.reg_path.exists())
        self.assertIsNone(self.state.data["credential"])

    def test_dpapi_save_failure_preserves_registration(self):
        with patch.object(self.state, "save", side_effect=OSError("failed")):
            self.assertEqual(self.invoke(), 1)
        self.assertTrue(self.reg_path.exists())
        self.assertIsNone(self.state.data["credential"])

    def test_after_enrollment_failure_resumes_without_token_reuse(self):
        original = self.central.send
        def fail_heartbeat(path, *args):
            if path == "/heartbeat": raise CentralError("NETWORK_ERROR")
            return original(path, *args)
        with patch.object(self.central, "send", side_effect=fail_heartbeat):
            self.assertEqual(self.invoke(), 1)
        self.assertTrue(self.reg_path.exists())
        self.assertIsNotNone(self.state.data["credential"])
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(sum(call[0] == "/enrollments" for call in self.central.calls), 1)

    def test_response_lost_preserves_file_no_automatic_enrollment_retry(self):
        with patch.object(self.central, "send", side_effect=CentralError("TOKEN_ALREADY_USED", 409)) as send:
            self.assertEqual(self.invoke(), 1)
            self.assertEqual(send.call_count, 1)
        self.assertTrue(self.reg_path.exists())

    def test_expired_wrong_family_or_header_does_not_enroll(self):
        for changes in ({"expires_at": "2000-01-01T00:00:00Z"}, {"family": "UNIX"}, {"enrollment_header": "Authorization"}):
            self.reg_path.write_text(json.dumps({**self.registration, **changes}), encoding="utf-8")
            self.assertEqual(self.invoke(), 1)
            self.assertTrue(self.reg_path.exists())
        self.assertEqual(self.central.calls, [])

    def test_ca_or_url_binding_failure_preserves_file(self):
        for changes in ({"ca_sha256_fingerprint": "b" * 64}, {"central_server_url": "https://wrong.example"}):
            self.reg_path.write_text(json.dumps({**self.registration, **changes}), encoding="utf-8")
            self.assertEqual(self.invoke(), 1)
            self.assertTrue(self.reg_path.exists())
        self.assertEqual(self.central.calls, [])

    def test_online_only_and_existing_identity_mismatch(self):
        self.assertEqual(self.invoke(), 0)
        self.central.calls.clear()
        self.assertEqual(self.invoke("online", ["--once"]), 0)
        # 동일 Inventory의 기존 ACK는 재사용한다. 변경 없는 관측을 강제로 재전송하지 않는다.
        self.assertEqual([call[0] for call in self.central.calls], ["/heartbeat", "/heartbeat"])
        self.assertIsNotNone(self.state.data["inventory_version"])
        self.reg_path.write_text(json.dumps({**self.registration, "enrollment_id": "different"}), encoding="utf-8")
        self.assertEqual(self.invoke(), 1)
        self.assertTrue(self.reg_path.exists())

    def test_online_receipt_binding_mismatch_refuses_requests(self):
        self.assertEqual(self.invoke(), 0)
        self.central.calls.clear()
        self.state.data["enrollment_receipt"]["central_server_url"] = "https://other.example/agent-api/v2"
        self.assertEqual(self.invoke("online", ["--once"]), 1)
        self.assertEqual(self.central.calls, [])
