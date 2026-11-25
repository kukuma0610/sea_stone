from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import winreg

from scripts import lab_hardening_e2e as lab
from scripts import lab_hardening_policy as policy
from tests import test_hardening_e2e as fixtures

script = fixtures.script

NOW = datetime(2026, 11, 25, 0, 30, tzinfo=timezone.utc)
VM = {"uuid": "11111111-1111-1111-1111-111111111111", "sid": "S-1-5-21-1-1001"}
COMMIT = "a" * 40


def record(code="W-07"):
    return {"policy_version": "LAB-E2E-1", "risk": policy.RISK,
            "approval_id": "22222222-2222-2222-2222-222222222222", "vm_uuid": VM["uuid"],
            "commit": COMMIT, "code": code, "max_uses": 1,
            "issued_at": NOW.isoformat(), "expires_at": (NOW+timedelta(hours=1)).isoformat(),
            "isolated_vm": True, "no_operating_data_or_credentials": True,
            "snapshot": {"id": "mock-snapshot", "confirmed": True, "recovery_procedure": "Mock VMware restore procedure"},
            "approvers": [
                {"role": "ADMINISTRATOR", "sid": VM["sid"], "accepted": True,
                 "approved_at": NOW.isoformat(), "reference": "mock-admin-record"},
                {"role": "TEST_OWNER", "sid": "S-1-5-21-1-1002", "accepted": True,
                 "approved_at": NOW.isoformat(), "reference": "mock-owner-record"}]}


class LabPolicyTests(unittest.TestCase):
    def validate(self, value):
        return policy.validate_approval(value, code="W-07", vm=VM, commit=COMMIT, now=NOW)

    def test_valid_record_and_missing_scope_risk_approval_rejections(self):
        self.assertEqual(len(self.validate(record())), 64)
        variants = [{"vm_uuid": "33333333-3333-3333-3333-333333333333"}, {"commit": "b"*40},
                    {"code": "W-13"}, {"max_uses": 2}, {"max_uses": True}, {"isolated_vm": False},
                    {"no_operating_data_or_credentials": False}, {"risk": "safe"},
                    {"expires_at": NOW.isoformat()}, {"expires_at": (NOW+timedelta(hours=5)).isoformat()},
                    {"approvers": []}, {"snapshot": {"id": "", "confirmed": False, "recovery_procedure": ""}}]
        for change in variants:
            with self.subTest(change=change), self.assertRaises(policy.LabRejected): self.validate({**record(), **change})
        for index in (0, 1):
            value = record()
            value["approvers"][index]["accepted"] = False
            with self.assertRaises(policy.LabRejected): self.validate(value)
        value = record()
        value["approvers"][1]["sid"] = VM["sid"]
        with self.assertRaises(policy.LabRejected): self.validate(value)

    def test_example_is_deliberately_non_approved(self):
        value = json.loads((policy.ROOT / "scripts/lab-approval.example.json").read_text())
        with self.assertRaises((ValueError, TypeError)): self.validate(value)

    def test_wrong_administrator_and_future_or_expired_approvals_reject(self):
        value = record()
        value["approvers"][0]["sid"] = "S-1-5-21-1-1999"
        with self.assertRaises(policy.LabRejected): self.validate(value)
        for field, date in (("issued_at", NOW+timedelta(minutes=1)),
                            ("expires_at", NOW-timedelta(minutes=1))):
            value = record()
            value[field] = date.isoformat()
            with self.subTest(field=field), self.assertRaises(policy.LabRejected): self.validate(value)

    def test_exact_history_only_and_other_path_read_failure(self):
        with patch.object(winreg, "OpenKey") as opened, patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), \
                patch.object(winreg, "EnumValue", return_value=("PolicyOverdue", 0, winreg.REG_DWORD)):
            opened.side_effect = [opened.return_value, FileNotFoundError()]
            policy.exact_history()
        for shape, entry in (((1, 1, 0), ("PolicyOverdue", 0, winreg.REG_DWORD)),
                             ((0, 2, 0), ("PolicyOverdue", 0, winreg.REG_DWORD)),
                             ((0, 1, 0), ("Other", 0, winreg.REG_DWORD)),
                             ((0, 1, 0), ("PolicyOverdue", "0", winreg.REG_SZ)),
                             ((0, 1, 0), ("PolicyOverdue", 1, winreg.REG_DWORD))):
            with self.subTest(entry=entry, shape=shape), patch.object(winreg, "OpenKey"), \
                    patch.object(winreg, "QueryInfoKey", return_value=shape), patch.object(winreg, "EnumValue", return_value=entry), \
                    self.assertRaises(policy.LabRejected): policy.exact_history()
        with patch.object(winreg, "OpenKey", side_effect=PermissionError), self.assertRaises(PermissionError): policy.exact_history()
        with patch.object(winreg, "OpenKey") as opened, patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), \
                patch.object(winreg, "EnumValue", return_value=("PolicyOverdue", 0, winreg.REG_DWORD)), self.assertRaises(PermissionError):
            opened.side_effect = [opened.return_value, PermissionError()]
            policy.exact_history()

    def test_environment_exception_is_not_a_global_bypass(self):
        error = policy.e2e.EnvironmentDiagnosticError("POLICY_HISTORY_FOUND", "POLICY_HISTORY", "unknown")
        error.history_detail = "POLICY_OVERDUE_SEMANTICS_UNVERIFIED"
        with patch.object(policy.e2e, "_is_administrator", return_value=True), patch.object(policy, "diagnose") as live, \
                patch.object(policy.e2e, "require_local_policy", side_effect=error), patch.object(policy, "exact_history") as history:
            policy.environment()
            live.assert_called_once()
            history.assert_called_once()
        for exc in (policy.e2e.EnvironmentDiagnosticError("DOMAIN_JOINED", "DOMAIN", ""), PermissionError(),
                    policy.e2e.EnvironmentDiagnosticError("POLICY_HISTORY_FOUND", "POLICY_HISTORY", "other")):
            with patch.object(policy.e2e, "_is_administrator", return_value=True), patch.object(policy, "diagnose"), \
                    patch.object(policy.e2e, "require_local_policy", side_effect=exc), patch.object(policy, "exact_history") as history:
                with self.assertRaises((policy.LabRejected, PermissionError)): policy.environment()
                history.assert_not_called()

    def test_live_failure_and_non_admin_never_reach_history_exception(self):
        with patch.object(policy.e2e, "_is_administrator", return_value=False), patch.object(policy, "diagnose") as live:
            with self.assertRaises(policy.LabRejected): policy.environment()
            live.assert_not_called()
        with patch.object(policy.e2e, "_is_administrator", return_value=True), \
                patch.object(policy, "diagnose", side_effect=ValueError("failed session")), \
                patch.object(policy.e2e, "require_local_policy") as operational:
            with self.assertRaises(ValueError): policy.environment()
            operational.assert_not_called()

    def test_state_gpo_list_policy_values_or_subkeys_are_blocked(self):
        for state in ((1, 0, 0), (0, 1, 0)):
            with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", side_effect=[(0, 1, 0), state]), \
                    patch.object(winreg, "EnumValue", return_value=("PolicyOverdue", 0, winreg.REG_DWORD)), \
                    patch.object(policy, "describe_gpo_list"), \
                    self.subTest(state=state), self.assertRaises(policy.LabRejected):
                policy.exact_history()

    def test_changed_or_uncommitted_source_is_not_approved(self):
        with patch.object(policy.subprocess, "check_output", side_effect=[COMMIT, "agent/checks/w07.py"]), \
                self.assertRaises(policy.LabRejected): policy.source_commit()
        with patch.object(policy.subprocess, "check_output", side_effect=[COMMIT, "", "scripts/other.py"]), \
                self.assertRaises(policy.LabRejected): policy.source_commit()
        with patch.object(policy.subprocess, "check_output", side_effect=[COMMIT, "", "", "tracked", "tracked"]):
            self.assertEqual(policy.source_commit(), COMMIT)

    def test_one_use_and_global_recovery_lock(self):
        with TemporaryDirectory() as temp, patch.object(policy, "lab_state_root", return_value=Path(temp)/"ledger"), patch.object(policy, "restrict_acl"):
            lease = policy.Lease(record(), "digest")
            lease.acquire()
            with self.assertRaises(FileExistsError): policy.Lease(record(), "digest").acquire()
            lease.release()
            with self.assertRaises(FileExistsError): policy.Lease(record(), "digest").acquire()
            self.assertFalse(lease.lock.exists())


class LabRunnerTests(unittest.TestCase):
    def test_duplicate_json_fields_and_non_admin_are_rejected(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "approval.json"
            path.write_text('{"code":"W-07","code":"W-13"}')
            with self.assertRaises(policy.LabRejected): lab.load_record(path)
        with patch.object(lab.e2e, "_is_administrator", return_value=False), patch.object(lab, "load_record") as load, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(lab.main(["--code", "W-07", "--approval-file", "mock.json", "--execute"]), 1)
            load.assert_not_called()
    def test_missing_approval_and_declined_risk_cannot_enter_execution(self):
        with patch.object(lab, "run") as execute, redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit): lab.main(["--code", "W-07", "--execute"])
            execute.assert_not_called()
        with patch.object(lab.e2e, "_is_administrator", return_value=True), patch.object(lab, "load_record", return_value=record()), \
                patch.object(policy, "identity", return_value=VM), patch.object(policy, "source_commit", return_value=COMMIT), \
                patch.object(policy, "validate_approval", return_value="digest"), patch.object(policy, "environment"), \
                patch.object(lab, "run") as execute, patch("builtins.input", return_value="no"), redirect_stdout(io.StringIO()):
            self.assertEqual(lab.main(["--code", "W-07", "--approval-file", "mock.json", "--execute"]), 1)
            execute.assert_not_called()

    def test_default_validates_only_without_snapshot_or_lease(self):
        with patch.object(lab.e2e, "_is_administrator", return_value=True), patch.object(lab, "load_record", return_value=record()), \
                patch.object(policy, "identity", return_value=VM), patch.object(policy, "source_commit", return_value=COMMIT), \
                patch.object(policy, "validate_approval", return_value="digest"), patch.object(policy, "environment") as env, \
                patch.object(lab, "run") as execute, patch("builtins.input") as prompt, redirect_stdout(io.StringIO()):
            self.assertEqual(lab.main(["--code", "W-07", "--approval-file", "mock.json"]), 0)
            env.assert_called_once()
            execute.assert_not_called()
            prompt.assert_not_called()

    def test_mock_all_18_prepare_harden_rollback_and_original_restore(self):
        case = fixtures.HardeningE2EScriptTests()
        for code in sorted(script.SEMI_AUTO_ALLOWLIST):
            with self.subTest(code=code), case.environment(code) as (action, capture, folder, output), \
                    patch.object(lab, "e2e", script), patch.object(policy, "lab_state_root", return_value=folder/"results/lab-hardening"), patch.object(policy, "restrict_acl"):
                before = capture()
                self.assertEqual(lab.run(record(code), "digest", lambda: None, evidence_kind="MOCK_UNIT_TEST"), 0)
                self.assertEqual(capture(), before)
                result = json.loads(next((folder / "results/lab-hardening").glob("*.result.json")).read_text(encoding="utf-8"))
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(result["test_policy_used"])
                self.assertFalse(result["central_approved"])
                self.assertEqual(result["execution_kind"], "MOCK_UNIT_TEST")
                self.assertEqual(result["stages"]["original_restore"], "PASS")
                self.assertEqual(result["prepared_check_status"], "FAIL")
                self.assertEqual(result["after_check_status"], "PASS")
                self.assertEqual(result["rollback_check_status"], "FAIL")
                self.assertEqual(result["original_check_status"], result["restored_check_status"])
                self.assertTrue(result["item_name"])
                self.assertTrue(list((folder/"results/lab-hardening").glob("*.console.log")))
                self.assertFalse((folder / "results/lab-hardening/ACTIVE_OR_RECOVERY_REQUIRED").exists())

    def test_partial_preparation_failure_restores_original(self):
        with fixtures.HardeningE2EScriptTests().environment("W-08") as (action, capture, folder, output), \
                patch.object(lab, "e2e", script), patch.object(policy, "lab_state_root", return_value=folder/"results/lab-hardening"), patch.object(policy, "restrict_acl"):
            before = capture()
            action.backend.fail_at = 2
            self.assertEqual(lab.run(record("W-08"), "digest", lambda: None, evidence_kind="MOCK_UNIT_TEST"), 1)
            self.assertEqual(capture(), before)

    def test_approval_decline_after_preparation_restores_and_consumes_receipt(self):
        with fixtures.HardeningE2EScriptTests().environment("W-07") as (action, capture, folder, output), \
                patch.object(lab, "e2e", script), patch.object(policy, "lab_state_root", return_value=folder/"results/lab-hardening"), \
                patch.object(policy, "restrict_acl"), patch("builtins.input", side_effect=["PREPARE W-07", "no"]):
            before = capture()
            self.assertEqual(lab.run(record(), "digest", lambda: None, evidence_kind="MOCK_UNIT_TEST"), 1)
            self.assertEqual(capture(), before)
            self.assertTrue(list((folder/"results/lab-hardening").glob("*.used")))

    def test_failed_recheck_cannot_return_pass_and_restores_original(self):
        with fixtures.HardeningE2EScriptTests().environment("W-07") as (action, capture, folder, output), \
                patch.object(lab, "e2e", script), patch.object(policy, "lab_state_root", return_value=folder/"results/lab-hardening"), \
                patch.object(policy, "restrict_acl"):
            before = capture()
            factory = script.HardeningRunner.side_effect
            def failed_recheck(*args, **kwargs):
                runner = factory(*args, **kwargs)
                real = runner._checker
                calls = [0]
                def checker(*args):
                    calls[0] += 1
                    observed = real(*args)
                    if calls[0] == 2:
                        from dataclasses import replace
                        return replace(observed, status="UNABLE")
                    return observed
                runner._checker = checker
                return runner
            with patch.object(script, "HardeningRunner", side_effect=failed_recheck):
                self.assertEqual(lab.run(record(), "digest", lambda: None, evidence_kind="MOCK_UNIT_TEST"), 1)
            self.assertEqual(capture(), before)
            result = json.loads(next((folder/"results/lab-hardening").glob("*.result.json")).read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "FAIL")

    def test_original_restore_failure_holds_global_lock_for_next_code(self):
        with fixtures.HardeningE2EScriptTests().environment("W-49") as (action, capture, folder, output), \
                patch.object(lab, "e2e", script), patch.object(policy, "lab_state_root", return_value=folder/"results/lab-hardening"), patch.object(policy, "restrict_acl"):
            restore, calls = action.restore, [0]
            def fail_final(snapshot):
                calls[0] += 1
                if calls[0] == 2: raise OSError("private-value")
                restore(snapshot)
            with patch.object(action, "restore", side_effect=fail_final):
                self.assertEqual(lab.run(record("W-49"), "digest", lambda: None, evidence_kind="MOCK_UNIT_TEST"), 1)
            self.assertTrue((folder / "results/lab-hardening/ACTIVE_OR_RECOVERY_REQUIRED").exists())
            other = record("W-07")
            other["approval_id"] = "33333333-3333-3333-3333-333333333333"
            with self.assertRaises(FileExistsError): policy.Lease(other, "digest").acquire()
            self.assertNotIn("private-value", output.getvalue())
