import importlib.util
import io
from contextlib import ExitStack, contextmanager, redirect_stdout
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent.windows_checks import collect_check
from agent.hardening import HardeningRunner, SnapshotStore
from agent.hardening.actions import RegistryValueAction
from agent.hardening.registry import get_action
from agent.hardening.policy_actions import new_actions
from tests.test_hardening_expansion import Backend, CheckApi, INITIAL

spec = importlib.util.spec_from_file_location(
    "hardening_e2e_script", Path(__file__).resolve().parents[1] / "scripts/test_hardening_e2e.py")
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

class HardeningE2EScriptTests(unittest.TestCase):
    @contextmanager
    def environment(self, code):
        actions = new_actions()
        if code in actions:
            action = actions[code]
            values = action.transform(deepcopy(INITIAL[code]))
            if code == "W-08": values = [120, 90, 3]
            if code == "W-09": values = [1, 20, 24, 30, 2]
            if code == "W-49": values = [["S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-551"]]
            backend = Backend(action, values)
            action.backend = backend
            api = CheckApi(backend)
            capture = action.capture
        else:
            action = get_action(code)
            state = {"exists": True, "value": action.target_value,
                     "registry_type": 1 if action.value_type == "SZ" else 4}
            if code == "W-52": state["registry_type"] = 2
            def capture_action(self): return deepcopy(state)
            def apply_action(self):
                state.update(exists=True, value=self.target_value,
                             registry_type=1 if self.value_type == "SZ" else 4)
            def restore_action(self, snapshot):
                state.update(exists=snapshot["existed"], value=snapshot["previous_value"],
                             registry_type=snapshot["value_type"])
            names = {
                "W-07": "everyone_includes_anonymous", "W-13": "blank_password_use_restricted",
                "W-15": "strong_key_protection_level", "W-48": "shutdown_without_logon",
                "W-50": "crash_on_audit_fail", "W-52": "auto_admin_logon",
                "W-53": "removable_media_eject_policy", "W-59": "lan_manager_authentication_level",
            }
            boolean = code in {"W-07", "W-13", "W-48", "W-50"}
            def value():
                if not state["exists"]: return None
                number = int(state["value"])
                return bool(number) if boolean else number
            api = SimpleNamespace(**{names[code]: value})
            capture = lambda: deepcopy(state)
        def checker(item, unused=None): return collect_check(item, api)
        def factory(gate, **kwargs):
            return HardeningRunner(gate, **kwargs, checker=checker, administrator_check=lambda: True)
        with ExitStack() as stack:
            temp = stack.enter_context(TemporaryDirectory())
            if isinstance(action, RegistryValueAction):
                stack.enter_context(patch.object(RegistryValueAction, "capture", capture_action))
                stack.enter_context(patch.object(RegistryValueAction, "apply", apply_action))
                stack.enter_context(patch.object(RegistryValueAction, "restore", restore_action))
            stack.enter_context(patch.object(script, "PROJECT_ROOT", Path(temp)))
            stack.enter_context(patch.object(script, "_is_administrator", return_value=True))
            stack.enter_context(patch.object(script, "require_local_policy"))
            stack.enter_context(patch.object(script, "get_action", return_value=action))
            stack.enter_context(patch.object(script, "collect_check", side_effect=checker))
            stack.enter_context(patch.object(script, "HardeningRunner", side_effect=factory))
            stack.enter_context(patch("agent.hardening.runner.get_action", return_value=action))
            stack.enter_context(patch("builtins.input", side_effect=[f"PREPARE {code}", f"APPROVE {code}"]))
            output = stack.enter_context(redirect_stdout(io.StringIO()))
            yield action, capture, Path(temp), output

    def test_all_eighteen_restore_original_values_types_and_sid_lists(self):
        for code in sorted(script.SEMI_AUTO_ALLOWLIST):
            with self.subTest(code=code), self.environment(code) as (action, capture, folder, output):
                original = capture()
                self.assertEqual(script.main(["--code", code]), 0)
                self.assertEqual(capture(), original)
                self.assertIn("[완료]", output.getvalue())
                self.assertEqual(len(list(folder.glob("results/hardening-e2e/originals/*.json"))), 1)
                self.assertEqual(len(list(folder.glob("results/hardening-snapshots/*.json"))), 1)

    def test_preparation_declined_changes_nothing(self):
        with self.environment("W-07") as (action, capture, folder, output):
            original = capture()
            with patch("builtins.input", return_value="no"):
                self.assertEqual(script.main(["--code", "W-07"]), 1)
            self.assertEqual(capture(), original)
            self.assertFalse(list(folder.glob("results/**/*.json")))

    def test_hardening_declined_still_restores_original(self):
        with self.environment("W-49") as (action, capture, folder, output):
            original = capture()
            with patch("builtins.input", side_effect=["PREPARE W-49", "no"]):
                self.assertEqual(script.main(["--code", "W-49"]), 1)
            self.assertEqual(capture(), original)
            self.assertIn("12.", output.getvalue())

    def test_backup_failure_prevents_preparation(self):
        with self.environment("W-09") as (action, capture, folder, output):
            original = capture()
            with patch.object(SnapshotStore, "create_transaction", side_effect=OSError("secret")), patch.object(script, "prepare_fail") as prepare:
                self.assertEqual(script.main(["--code", "W-09"]), 1)
                prepare.assert_not_called()
            self.assertEqual(capture(), original)
            self.assertNotIn("secret", output.getvalue())

    def test_partial_preparation_failure_restores_every_original_value(self):
        with self.environment("W-08") as (action, capture, folder, output):
            original = capture()
            action.backend.fail_at = 2
            self.assertEqual(script.main(["--code", "W-08"]), 1)
            self.assertEqual(capture(), original)
            self.assertIn("12.", output.getvalue())

    def test_non_admin_or_unknown_gpo_changes_nothing(self):
        for blocked in ("admin", "gpo"):
            with self.environment("W-07") as (action, capture, folder, output):
                original = capture()
                with patch.object(script, "_is_administrator", return_value=blocked != "admin"), patch.object(script, "require_local_policy", side_effect=RuntimeError("unknown")):
                    self.assertEqual(script.main(["--code", "W-07"]), 1)
                self.assertEqual(capture(), original)
                self.assertFalse(list(folder.glob("results/**/*.json")))

    def test_all_option_rejected(self):
        with redirect_stdout(io.StringIO()), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            script.main(["--all"])

    def test_original_absent_value_is_removed_at_final_restore(self):
        with self.environment("W-36") as (action, capture, folder, output):
            action.backend.entries[0].update(exists=False, value=None, type=None)
            original = capture()
            self.assertEqual(script.main(["--code", "W-36"]), 0)
            self.assertEqual(capture(), original)

    def test_hardening_failure_still_restores_original(self):
        with self.environment("W-09") as (action, capture, folder, output):
            original = capture()
            # 테스트 준비 한 번을 통과하고 다음 정책 변경 중 오류를 발생시킨다.
            action.backend.fail_at = 2
            self.assertEqual(script.main(["--code", "W-09"]), 1)
            self.assertEqual(capture(), original)
            self.assertIn("12.", output.getvalue())

    def test_final_restore_failure_is_reported_without_success(self):
        with self.environment("W-49") as (action, capture, folder, output):
            original_restore = action.restore
            calls = 0
            def restore(snapshot):
                nonlocal calls
                calls += 1
                if calls == 2: raise OSError("secret")
                original_restore(snapshot)
            with patch.object(action, "restore", side_effect=restore):
                self.assertEqual(script.main(["--code", "W-49"]), 1)
            self.assertIn("원본 복구 실패", output.getvalue())
            self.assertNotIn("[완료]", output.getvalue())
            self.assertNotIn("secret", output.getvalue())

    def test_check_failure_after_prepare_restores_original_without_leaking_error(self):
        with self.environment("W-07") as (action, capture, folder, output):
            original = capture()
            actual = script.collect_check.side_effect
            count = 0
            def checker(code):
                nonlocal count
                count += 1
                if count == 2: raise OSError("secret")
                return actual(code)
            with patch.object(script, "collect_check", side_effect=checker):
                self.assertEqual(script.main(["--code", "W-07"]), 1)
            self.assertEqual(capture(), original)
            self.assertNotIn("secret", output.getvalue())
