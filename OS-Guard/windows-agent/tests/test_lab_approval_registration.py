from contextlib import contextmanager, redirect_stdout
import ctypes
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from scripts import lab_approval_registration as registration
from scripts.lab_approval_pipe import ApprovalPipe
from scripts import lab_hardening_policy as policy

VM = {"uuid": "11111111-1111-1111-1111-111111111111", "sid": "S-1-5-21-1-1001"}
OWNER = "S-1-5-21-1-1002"
COMMIT = "a"*40


class MockDPAPI:
    def protect(self, raw): return b"MOCK-ONLY:"+raw
    def unprotect(self, raw):
        if not raw.startswith(b"MOCK-ONLY:"): raise ValueError("bad mock seal")
        return raw[len(b"MOCK-ONLY:"):]


class RegistrationTests(unittest.TestCase):
    @contextmanager
    def setup_registration(self):
        with TemporaryDirectory() as temp, patch.object(policy, "lab_state_root", return_value=Path(temp)/"state"), \
                patch.object(policy, "restrict_acl"), patch.object(policy.e2e, "_is_administrator", return_value=True), \
                patch.object(policy, "identity", return_value=VM), patch.object(policy, "source_commit", return_value=COMMIT), \
                patch.object(registration, "token_user", return_value=VM["sid"]), patch.object(policy, "environment"), \
                patch.object(registration.subprocess, "check_output", return_value=b"tracked"), \
                patch.object(registration, "owner_logon", return_value=OWNER) as owner, \
                patch.object(registration, "DPAPI", MockDPAPI), \
                patch("builtins.input", side_effect=["SNAPSHOT mock-snapshot", "ACCEPT W-07", ".\\mock-owner"]), \
                redirect_stdout(io.StringIO()) as output:
            yield Path(temp)/"state", owner, output

    def test_mock_registration_records_fresh_utc_identity_scope_and_never_hardens(self):
        with self.setup_registration() as (root, owner, output), patch.object(policy.e2e, "HardeningRunner") as harden:
            before = datetime.now(timezone.utc)
            target = registration.register("W-07", "mock-snapshot", evidence_kind="MOCK_UNIT_TEST")
            data = json.loads(target.read_text())
            self.assertEqual(data["commit"], COMMIT)
            self.assertEqual(data["vm_uuid"], VM["uuid"])
            self.assertEqual(data["code"], "W-07")
            self.assertEqual(data["approvers"][0]["sid"], VM["sid"])
            self.assertEqual(data["approvers"][1]["sid"], OWNER)
            for item in data["approvers"]:
                self.assertGreaterEqual(policy.utc(item["approved_at"]), before)
                self.assertTrue(item["accepted"])
            harden.assert_not_called()
            self.assertIn("--approval-file", output.getvalue())
            owner.assert_called_once()
            # Mock 자료는 실제 승인 검증으로 사용할 수 없다.
            with self.assertRaises(policy.LabRejected): registration.verify_registration(data)

    def test_mock_native_boundary_and_tampered_record_or_audit_are_rejected(self):
        with self.setup_registration() as (root, owner, output):
            target = registration.register("W-07", "mock-snapshot", evidence_kind="MOCK_UNIT_TEST")
            data = json.loads(target.read_text())
            audit = target.with_name(data["approval_id"]+".audit.jsonl")
            seal_path = target.with_name(data["approval_id"]+".audit.dpapi")
            # Windows 인증 경계는 Mock으로만 대체한다. 실제 VM 승인을 발급하는 테스트가 아니다.
            rows = [json.loads(line) for line in audit.read_text().splitlines()]
            for row in rows: row["kind"] = "NATIVE_WINDOWS_LOGON"
            raw = ("\n".join(json.dumps(row) for row in rows)+"\n").encode()
            audit.write_bytes(raw)
            import hashlib
            seal = {"approval_id": data["approval_id"], "approval_sha256": registration.digest(data),
                    "audit_sha256": hashlib.sha256(raw).hexdigest(), "kind": "NATIVE_WINDOWS_LOGON"}
            seal_path.write_bytes(MockDPAPI().protect(json.dumps(seal).encode()))
            registration.verify_registration(data)
            data["snapshot"]["id"] = "tampered"
            with self.assertRaises(policy.LabRejected): registration.verify_registration(data)
            data = json.loads(target.read_text())
            audit.write_bytes(raw+b"{}\n")
            with self.assertRaises(policy.LabRejected): registration.verify_registration(data)

    def test_declined_admin_or_owner_and_same_account_never_issue_approval(self):
        for kind in ("admin", "owner", "same"):
            with self.subTest(kind=kind), self.setup_registration() as (root, owner, output):
                if kind == "owner": owner.side_effect = policy.LabRejected("OWNER_RISK_NOT_ACCEPTED")
                if kind == "same": owner.return_value = VM["sid"]
                prompts = ["SNAPSHOT mock-snapshot", "no"] if kind == "admin" else ["SNAPSHOT mock-snapshot", "ACCEPT W-07", "owner"]
                with patch("builtins.input", side_effect=prompts), self.assertRaises(policy.LabRejected):
                    registration.register("W-07", "mock-snapshot", evidence_kind="MOCK_UNIT_TEST")
                self.assertFalse(list(root.rglob("*.approval.json")))
                self.assertFalse(list(root.rglob("*.audit.dpapi")))

    def test_existing_recovery_lock_blocks_registration(self):
        with self.setup_registration() as (root, owner, output):
            root.mkdir()
            (root/"ACTIVE_OR_RECOVERY_REQUIRED").write_text("mock recovery pending")
            with self.assertRaises(policy.LabRejected): registration.register("W-07", "mock-snapshot", evidence_kind="MOCK_UNIT_TEST")
            owner.assert_not_called()

    def test_new_logon_gpo_failure_never_issues_approval(self):
        with self.setup_registration() as (root, owner, output), \
                patch.object(policy, "environment", side_effect=[None, policy.LabRejected("ACTIVE_GPO")]):
            with self.assertRaises(policy.LabRejected): registration.register("W-07", "mock-snapshot", evidence_kind="MOCK_UNIT_TEST")
            self.assertFalse(list(root.rglob("*.approval.json")))

    def test_owner_login_checks_actual_pipe_sid_not_account_lookup_only(self):
        request = {"admin_sid": VM["sid"], "approval_id": "mock-id"}
        with patch.object(registration, "sid_for_account", return_value=OWNER), \
                patch.object(registration, "ApprovalPipe") as pipe_type, \
                patch.object(registration.subprocess, "Popen") as start:
            pipe = pipe_type.return_value
            pipe.approve.return_value = OWNER
            start.return_value.wait.return_value = 0
            start.return_value.poll.return_value = 0
            self.assertEqual(registration.owner_logon("owner", request), OWNER)
            self.assertIn("lab_owner_confirm.ps1", str(start.call_args.args[0]))
            self.assertFalse(start.call_args.kwargs["shell"])
            pipe.approve.return_value = "S-1-5-21-1-9999"
            with self.assertRaises(policy.LabRejected): registration.owner_logon("owner", request)

    def test_account_lookup_for_admin_is_not_owner_approval(self):
        with patch.object(registration, "sid_for_account", return_value=VM["sid"]), \
                patch.object(registration, "ApprovalPipe") as pipe:
            with self.assertRaises(policy.LabRejected): registration.owner_logon("admin", {"admin_sid": VM["sid"]})
            pipe.assert_not_called()

    def test_impersonation_failure_never_uses_server_identity_and_reverts_on_query_failure(self):
        pipe = object.__new__(ApprovalPipe)
        pipe.handle, pipe.a, pipe.k = 1, MagicMock(), MagicMock()
        pipe.a.ImpersonateNamedPipeClient.return_value = False
        with self.assertRaises(policy.LabRejected): pipe.peer_sid()
        pipe.a.OpenThreadToken.assert_not_called()
        pipe.a.RevertToSelf.reset_mock()
        pipe.a.ImpersonateNamedPipeClient.return_value = True
        pipe.a.OpenThreadToken.return_value = False
        pipe.a.RevertToSelf.return_value = True
        with self.assertRaises(policy.LabRejected): pipe.peer_sid()
        pipe.a.RevertToSelf.assert_called_once()

    def test_policy_does_not_accept_made_up_registration_reference(self):
        from tests.test_lab_hardening import record, VM as fixture_vm, COMMIT as fixture_commit, NOW
        value = record()
        for entry in value["approvers"]:
            entry["reference"] = registration.PREFIX+value["approval_id"]+":"+entry["role"]
        with patch.object(registration, "verify_registration", side_effect=ValueError("no protected record")), \
                self.assertRaises(policy.ApprovalFieldsRejected):
            policy.validate_approval(value, code="W-07", vm=fixture_vm, commit=fixture_commit, now=NOW)
