"""실제 레지스트리 CHECK 함수와 action을 가짜 winreg 저장소로 대조한다."""

from contextlib import contextmanager
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import winreg

from agent.checks.common import NativeWindowsReadOnlyApi
from agent.windows_checks import collect_check
from agent.hardening import ApprovalGate, HardeningRunner, SnapshotStore, create_plan
from agent.hardening.registry import get_action
from agent.hardening.policy_actions import PolicyTransactionAction


class RegistryAuditTests(unittest.TestCase):
    def test_malformed_registry_snapshot_is_rejected_before_write(self):
        action = get_action("W-07")
        snapshots = (
            {"existed": "false", "value_type": 4, "previous_value": 1},
            {"existed": False, "value_type": 4, "previous_value": 1},
            {"existed": True, "value_type": 4, "previous_value": "1"},
        )
        with patch.object(winreg, "CreateKeyEx") as write:
            for snapshot in snapshots:
                with self.assertRaises(ValueError): action.restore(snapshot)
            write.assert_not_called()

    def test_real_read_write_targets_and_original_types_for_twelve_registry_actions(self):
        cases = {
            "W-07": (1, 4), "W-13": (0, 4), "W-15": (1, 4),
            "W-48": (1, 4), "W-50": (1, 4), "W-52": ("1", 2),
            "W-53": ("1", 1), "W-59": (2, 4),
            "W-10": (0, 4), "W-28": (1, 4), "W-36": (3600000, 4), "W-55": (0, 4),
        }
        for code, original in cases.items():
            with self.subTest(code=code), TemporaryDirectory() as temp:
                action = get_action(code)
                target = action.targets[0] if isinstance(action, PolicyTransactionAction) else action
                name = target.key if isinstance(action, PolicyTransactionAction) else target.name
                values = {(target.path.casefold(), name.casefold()): original}
                @contextmanager
                def key(hive, path, *args):
                    self.assertEqual(hive, winreg.HKEY_LOCAL_MACHINE)
                    yield path.casefold()
                def query(path, name):
                    try: return values[(path, name.casefold())]
                    except KeyError: raise FileNotFoundError()
                def write(path, name, reserved, kind, value):
                    values[(path, name.casefold())] = (value, kind)
                def delete(path, name):
                    values.pop((path, name.casefold()), None)
                api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)
                api._service_running = lambda name: True
                def export(area="SECURITYPOLICY"):
                    value, kind = query(target.path.casefold(), name)
                    return f"[Registry Values]\nMACHINE\\{target.path}\\{name}={kind},{value}\n"
                api._export_security_policy = export
                with patch.object(winreg, "OpenKey", side_effect=key), patch.object(winreg, "CreateKeyEx", side_effect=key), patch.object(winreg, "QueryValueEx", side_effect=query), patch.object(winreg, "SetValueEx", side_effect=write), patch.object(winreg, "DeleteValue", side_effect=delete), patch("agent.hardening.policy_actions.WindowsPolicyBackend.verify"):
                    observation = collect_check(code, api)
                    self.assertEqual(observation.status, "FAIL")
                    gate = ApprovalGate()
                    plan = create_plan(observation)
                    approved, receipt = gate.approve(gate.request(plan), approved=True)
                    runner = HardeningRunner(gate, api=api, administrator_check=lambda: True, snapshot_store=SnapshotStore(temp))
                    result = runner.run(approved, receipt)
                    self.assertEqual(result.state, "SUCCESS")
                    self.assertEqual(collect_check(code, api).status, "PASS")
                    rollback = runner.rollback(code=code, plan_id=plan.plan_id, snapshot_id=result.snapshot_id)
                    self.assertTrue(rollback.success)
                    self.assertEqual(values[(target.path.casefold(), name.casefold())], original)
                    self.assertEqual(collect_check(code, api).status, "FAIL")
