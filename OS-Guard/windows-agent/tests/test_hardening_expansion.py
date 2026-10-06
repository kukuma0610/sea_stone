"""새 조치도 실제 W-code 판정기를 사용하되 Windows 변경은 전부 mock 처리한다."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent.windows_checks import collect_check
from agent.hardening import ApprovalGate, HardeningRunner, SnapshotStore, create_plan, HardeningRejected
from agent.hardening.policy_actions import (
    PolicySafetyError, PolicyPreconditionError, WindowsPolicyBackend, new_actions,
    verify_rsop, verify_local_gpo_files, require_local_policy, lockout_periods, password_policy, idle_timeout,
)
from agent.hardening.registry import get_action, SEMI_AUTO_ALLOWLIST


INITIAL = {
    "W-04": [60, 60, 8], "W-05": [1], "W-08": [20, 20, 3],
    "W-09": [0, 6, 2, 120, 0], "W-10": [0], "W-12": [1],
    "W-28": [1], "W-36": [3600000], "W-49": [["S-1-5-32-544", "S-1-5-32-545"]],
    "W-55": [0],
}


class Backend:
    def __init__(self, action, values):
        self.entries = [dict(target.identity(), exists=value is not None, value=value,
                             type=(4 if target.path else "SID_LIST" if isinstance(value, list) else "POLICY_INTEGER")
                             if value is not None else None)
                        for target, value in zip(action.targets, values)]
        self.writes = 0
        self.fail_at = None
        self.blocked = False

    def verify(self):
        if self.blocked:
            raise PolicySafetyError("domain or GPO")

    def read(self, target):
        return deepcopy(next(e for e in self.entries if e["name"] == target.key))

    def write(self, target, entry):
        self.writes += 1
        if self.writes == self.fail_at:
            raise OSError("mock middle write failure")
        index = next(i for i, e in enumerate(self.entries) if e["name"] == target.key)
        self.entries[index] = deepcopy(entry)


class CheckApi:
    def __init__(self, backend):
        self.backend = backend

    def values(self):
        return [e["value"] for e in self.backend.entries]

    def lockout_threshold(self): return self.values()[2]
    def lockout_policy(self):
        duration, reset, threshold = self.values()
        return {"duration_seconds": duration * 60, "reset_seconds": reset * 60, "threshold": threshold}
    def domain_joined(self): return False
    def reversible_password_encryption_enabled(self): return bool(self.values()[0])
    def password_policy(self):
        complexity, length, history, maximum, minimum = self.values()
        return {"complexity_enabled": complexity, "minimum_length": length, "history_length": history,
                "maximum_age_seconds": maximum * 86400, "minimum_age_seconds": minimum * 86400}
    def dont_display_last_username(self): return bool(self.values()[0])
    def anonymous_sid_name_translation_enabled(self): return bool(self.values()[0])
    def rdp_inventory(self): return {"service_running": True, "minimum_encryption_level": self.values()[0]}
    def remote_idle_timeout_minutes(self):
        value = self.values()[0]
        return None if value is None else value // 60000
    def remote_shutdown_principal_counts(self):
        sids = self.values()[0]
        return {"principal_count": len(sids), "unexpected_principal_count": sum(s != "S-1-5-32-544" for s in sids)}
    def printer_driver_installation_prevented(self): return bool(self.values()[0])


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = SnapshotStore(self.temp.name)

    def setup_code(self, code, values=None):
        action = new_actions()[code]
        backend = Backend(action, deepcopy(INITIAL[code] if values is None else values))
        action.backend = backend
        api = CheckApi(backend)
        gate = ApprovalGate()
        plan = create_plan(collect_check(code, api))
        approved, receipt = gate.approve(gate.request(plan), approved=True)
        runner = HardeningRunner(gate, api=api, administrator_check=lambda: True, snapshot_store=self.store)
        return action, backend, api, plan, approved, receipt, runner

    def success_and_rollback(self, code):
        action, backend, api, plan, approved, receipt, runner = self.setup_code(code)
        before = deepcopy(backend.entries)
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
            self.assertEqual(result.state, "SUCCESS")
            self.assertEqual(collect_check(code, api).status, "PASS")
            snapshot = self.store.load(result.snapshot_id)
            self.assertEqual(snapshot.targets, before)
            self.assertEqual(snapshot.plan_id, plan.plan_id)
            rollback = runner.rollback(code=code, plan_id=plan.plan_id, snapshot_id=result.snapshot_id)
        self.assertTrue(rollback.success)
        self.assertEqual(backend.entries, before)
        self.assertEqual(collect_check(code, api).status, "FAIL")

    def test_w04(self): self.success_and_rollback("W-04")
    def test_w05(self): self.success_and_rollback("W-05")
    def test_w08(self): self.success_and_rollback("W-08")
    def test_w09(self): self.success_and_rollback("W-09")
    def test_w10(self): self.success_and_rollback("W-10")
    def test_w12(self): self.success_and_rollback("W-12")
    def test_w28(self): self.success_and_rollback("W-28")
    def test_w36(self): self.success_and_rollback("W-36")
    def test_w49(self): self.success_and_rollback("W-49")
    def test_w55(self): self.success_and_rollback("W-55")

    def test_all_new_codes_require_approval_and_admin(self):
        for code in INITIAL:
            with self.subTest(code=code):
                action, backend, api, plan, approved, receipt, runner = self.setup_code(code)
                with self.assertRaises(HardeningRejected):
                    runner.run(plan, receipt)
                runner._administrator_check = lambda: False
                with self.assertRaises(HardeningRejected):
                    runner.run(approved, receipt)
                self.assertEqual(backend.writes, 0)

    def test_allowlist_and_non_fail_blocking(self):
        self.assertEqual(len(SEMI_AUTO_ALLOWLIST), 18)
        with self.assertRaises(ValueError): get_action("W-64")
        for status in ("PASS", "NA", "UNABLE"):
            with self.assertRaises(ValueError): create_plan({"item_id": "W-09", "status": status})

    def test_middle_failure_restores_every_policy(self):
        for code in ("W-08", "W-09"):
            with self.subTest(code=code):
                action, backend, api, plan, approved, receipt, runner = self.setup_code(code)
                original = deepcopy(backend.entries)
                backend.fail_at = 2
                with patch("agent.hardening.runner.get_action", return_value=action):
                    result = runner.run(approved, receipt)
                self.assertEqual(result.state, "FAILED")
                self.assertTrue(result.rollback.success)
                self.assertEqual(backend.entries, original)

    def test_recheck_failure_restores_all_targets(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-09")
        original = deepcopy(backend.entries)
        runner._checker = lambda code, api: collect_check(code, CheckApi(Backend(action, INITIAL[code])))
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
        self.assertEqual(result.state, "FAILED")
        self.assertTrue(result.rollback.success)
        self.assertEqual(backend.entries, original)

    def test_absent_registry_value_restored_to_absent(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-36", [None])
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
            rollback = runner.rollback(code="W-36", plan_id=plan.plan_id, snapshot_id=result.snapshot_id)
        self.assertTrue(rollback.success)
        self.assertFalse(backend.entries[0]["exists"])

    def test_gpo_refusal_and_unverifiable_state_no_writes(self):
        for code in INITIAL:
            action, backend, api, plan, approved, receipt, runner = self.setup_code(code)
            backend.blocked = True
            with patch("agent.hardening.runner.get_action", return_value=action):
                result = runner.run(approved, receipt)
            self.assertEqual(result.state, "FAILED")
            self.assertIsNone(result.snapshot_id)
            self.assertEqual(backend.writes, 0)

    def test_preserves_stronger_values_and_rejects_weakening(self):
        self.assertEqual(password_policy([0, 20, 24, 30, 2]), [1, 20, 24, 30, 2])
        self.assertEqual(lockout_periods([120, 30, 3]), [120, 60, 3])
        self.assertEqual(idle_timeout([600000]), [600000])
        with self.assertRaises(PolicySafetyError): idle_timeout([30000])
        with self.assertRaises(PolicySafetyError): password_policy([0, 20, 24, 365, 120])

    def test_policy_changes_since_snapshot_do_not_overwrite_external_changes(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-09")
        before = action.capture()
        backend.entries[0]["value"] = 1
        with self.assertRaises(PolicyPreconditionError): action.apply(before)
        self.assertEqual(backend.writes, 0)

    def test_precondition_failure_after_snapshot_does_not_trigger_writes(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-36", [30000])
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
        self.assertEqual(result.state, "FAILED")
        self.assertIsNone(result.rollback)
        self.assertEqual(backend.writes, 0)

    def test_snapshot_save_failure_prevents_apply(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-09")
        with patch("agent.hardening.runner.get_action", return_value=action), patch.object(self.store, "create_transaction", side_effect=OSError("mock disk failure")):
            result = runner.run(approved, receipt)
        self.assertEqual(result.state, "FAILED")
        self.assertEqual(backend.writes, 0)

    def test_backend_command_failure_is_not_hidden_and_shell_disabled(self):
        from agent.hardening.policy_actions import run_fixed
        with patch("agent.hardening.policy_actions.subprocess.run") as execute:
            execute.return_value.returncode = 1
            with self.assertRaises(PolicySafetyError): run_fixed(["secedit.exe", "/configure"])
            self.assertIs(execute.call_args.kwargs["shell"], False)

    def test_tampered_snapshot_target_is_rejected_before_write(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-09")
        targets = action.capture()["targets"]
        targets[0]["name"] = "InjectedPolicy"
        with self.assertRaises(PolicySafetyError): action.restore({"targets": targets})
        self.assertEqual(backend.writes, 0)

    def test_restore_continues_after_one_target_fails(self):
        action, backend, api, plan, approved, receipt, runner = self.setup_code("W-09")
        before = action.capture()
        backend.fail_at = 1
        with self.assertRaises(PolicySafetyError): action.restore(before)
        self.assertEqual(backend.writes, 5)

    def test_rsop_requires_proven_local_gpo(self):
        verify_rsop(b"<Rsop><ComputerResults><GPO><Path>LocalGPO</Path></GPO></ComputerResults></Rsop>")
        for xml in (b"<Rsop/>", b"<Rsop><ComputerResults/></Rsop>",
                    b"<Rsop><ComputerResults><GPO><Path>LDAP://domain</Path></GPO></ComputerResults></Rsop>"):
            with self.assertRaises(PolicySafetyError): verify_rsop(xml)

    def test_local_gpo_files_block_reapplication(self):
        root = Path(self.temp.name)
        verify_local_gpo_files(root)
        machine = root / "GroupPolicy" / "Machine"
        machine.mkdir(parents=True)
        registry = machine / "Registry.pol"
        registry.write_bytes(b"PReg\x01\x00\x00\x00")
        verify_local_gpo_files(root)
        registry.write_bytes(b"configured policy")
        with self.assertRaises(PolicySafetyError): verify_local_gpo_files(root)

    def test_security_policy_reader_selects_exact_section(self):
        target = new_actions()["W-05"].targets[0]
        backend = WindowsPolicyBackend()
        with patch("agent.hardening.policy_actions.NativeWindowsReadOnlyApi") as api:
            api.return_value._export_security_policy.return_value = "[Other]\nClearTextPassword=9\n[System Access]\nClearTextPassword=1\n"
            self.assertEqual(backend.read(target)["value"], 1)
            api.return_value._export_security_policy.return_value = "[System Access]\nOther=1\n"
            with self.assertRaises(PolicySafetyError): backend.read(target)

    def test_export_units_must_exactly_match_native_check_values(self):
        target = new_actions()["W-08"].targets[0]
        backend = WindowsPolicyBackend()
        with patch("agent.hardening.policy_actions.NativeWindowsReadOnlyApi") as api:
            api.return_value._export_security_policy.return_value = "[System Access]\nLockoutDuration=60\n"
            api.return_value.lockout_policy.return_value = {"duration_seconds": 3600}
            self.assertEqual(backend.read(target)["value"], 60)
            api.return_value.lockout_policy.return_value = {"duration_seconds": 3599}
            with self.assertRaises(PolicySafetyError): backend.read(target)

    def test_domain_refused_before_any_apply(self):
        with patch("agent.hardening.policy_actions.NativeWindowsReadOnlyApi") as api, patch("agent.hardening.policy_actions.run_fixed") as execute:
            api.return_value.windows_os_info.return_value = {"caption": "Windows Server 2022"}
            api.return_value.domain_joined.return_value = True
            with self.assertRaises(PolicySafetyError): require_local_policy()
            execute.assert_not_called()

    def test_fixed_template_writer_has_only_allowlisted_keys(self):
        action = new_actions()["W-05"]
        backend = WindowsPolicyBackend()
        entry = {**action.targets[0].identity(), "exists": True, "value": 0, "type": "POLICY_INTEGER"}
        captured = []
        def fixed(args):
            captured.append(args)
            cfg = Path(args[args.index("/cfg") + 1]).read_text(encoding="utf-16")
            self.assertIn("ClearTextPassword = 0", cfg)
            self.assertNotIn("PasswordComplexity", cfg)
        with patch("agent.hardening.policy_actions.system_executable", return_value="secedit.exe"), patch("agent.hardening.policy_actions.run_fixed", side_effect=fixed):
            backend.write(action.targets[0], entry)
        self.assertEqual(captured[0][captured[0].index("/areas") + 1], "SECURITYPOLICY")
