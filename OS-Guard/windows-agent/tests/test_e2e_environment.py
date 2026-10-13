from copy import deepcopy
import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch
import winreg

from tests.test_hardening_e2e import script
from agent.hardening.policy_actions import PolicySafetyError


class E2EEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.info = dict(version="10.0.20348", build="20348", product_type=3,
                         domain_joined=False, domain_role=2, gpo_state="verified", gpos=[])

    def verify(self, info):
        with patch.object(script, "collect_environment", return_value=info), patch.object(script, "system_executable", return_value="C:/Windows/System32/gpresult.exe"), patch.object(script, "verify_local_gpo_files"), patch.object(script, "verify_no_policy_history"):
            script.require_local_policy()

    def test_workgroup_server_with_no_gpos_allowed(self):
        self.verify(self.info)

    def test_empty_local_gpo_allowed_without_localized_names(self):
        self.info["gpos"] = [{"id": "LocalGPO"}]
        self.verify(self.info)

    def test_namespace_absent_requires_independent_empty_policy_checks(self):
        self.info["gpo_state"] = "namespace_absent"
        self.verify(self.info)
        with patch.object(script, "collect_environment", return_value=self.info), patch.object(script, "system_executable", return_value="C:/Windows/System32/gpresult.exe"), patch.object(script, "verify_local_gpo_files", side_effect=PolicySafetyError("configured")):
            with self.assertRaises(PolicySafetyError): script.require_local_policy()

    def test_domain_and_applied_gpo_remain_rejected(self):
        for changes in ({"domain_joined": True, "domain_role": 3},
                        {"gpos": [{"id": "{domain-gpo-id}"}]},
                        {"gpo_state": "failed"}, {"gpos": None},
                        {"domain_joined": None}, {"product_type": 1},
                        {"version": "10.0.17763"}, {"domain_role": 4}):
            with self.subTest(changes=changes), self.assertRaises(PolicySafetyError):
                self.verify({**deepcopy(self.info), **changes})

    def test_history_absence_is_not_the_same_as_access_denied(self):
        with patch.object(winreg, "OpenKey", side_effect=FileNotFoundError):
            script.verify_no_policy_history()
        with patch.object(winreg, "OpenKey", side_effect=PermissionError):
            with self.assertRaises(PermissionError): script.verify_no_policy_history()
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(1, 0, 0)), patch.object(winreg, "EnumKey", return_value="{real-gpo-guid}"):
            with self.assertRaises(PolicySafetyError): script.verify_no_policy_history()

    def test_structured_collection_does_not_invoke_gpresult(self):
        with patch.object(script, "NativeWindowsReadOnlyApi") as api:
            api.return_value._run_powershell_json.return_value = [self.info]
            self.assertEqual(script.collect_environment(), self.info)
            query = api.return_value._run_powershell_json.call_args.args[0]
            self.assertIn("Win32_OperatingSystem", query)
            self.assertIn("RSOP_GPO", query)
            self.assertNotIn("gpresult", query)
            self.assertNotIn("Caption", query)
            api.return_value._run_powershell_json.side_effect = OSError("query failed")
            with self.assertRaises(OSError): script.collect_environment()

    def test_query_failure_preserves_stage_and_message(self):
        for location, reason in (("OS_CIM", "CIM_QUERY_FAILED"), ("COMPUTER_CIM", "CIM_QUERY_FAILED"),
                                 ("GPO_CIM", "GPO_QUERY_FAILED")):
            with self.subTest(location=location), patch.object(script, "NativeWindowsReadOnlyApi") as api:
                api.return_value._run_powershell_json.return_value = [{**self.info, "diagnostic_error":
                    {"location": location, "exception_type": "CimException", "message": "Access denied"}}]
                with redirect_stdout(io.StringIO()), self.assertRaises(script.EnvironmentDiagnosticError) as error:
                    script.collect_environment()
                self.assertEqual(error.exception.reason_code, reason)
                self.assertEqual(error.exception.location, location)
                self.assertIn("Access denied", str(error.exception))

    @patch.object(script, "diagnose_live_gpo", new=lambda: None)
    def test_diagnose_option_never_checks_or_changes_registry(self):
        with patch.object(script, "_is_administrator", return_value=True), patch.object(script, "require_local_policy"), patch.object(script, "get_action") as action, patch.object(script, "collect_check") as check, patch.object(script, "prepare_fail") as prepare, patch("builtins.input") as approval, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(script.main(["--code", "W-07", "--diagnose-env"]), 0)
            action.assert_not_called()
            check.assert_not_called()
            prepare.assert_not_called()
            approval.assert_not_called()
            self.assertIn("진단 전용", output.getvalue())

    @patch.object(script, "diagnose_live_gpo", new=lambda: None)
    def test_skip_prints_reason_location_and_exception_message(self):
        error = script.EnvironmentDiagnosticError("GPO_QUERY_FAILED", "GPO_CIM", "Invalid class")
        with patch.object(script, "_is_administrator", return_value=True), patch.object(script, "require_local_policy", side_effect=error), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(script.main(["--code", "W-07", "--diagnose-env"]), 1)
        for text in ("GPO_QUERY_FAILED", "GPO_CIM", "Invalid class", "[SKIP]"):
            self.assertIn(text, output.getvalue())

    def test_success_diagnostics_show_all_environment_fields(self):
        with redirect_stdout(io.StringIO()) as output:
            self.verify(self.info)
        for text in ("OS 판정: PASS", "Build=20348", "ProductType=3", "PartOfDomain=False", "GPO 조회=verified", "적용 GPO 개수=0"):
            self.assertIn(text, output.getvalue())

    def test_known_link_metadata_is_not_gpo_application_history(self):
        for value in (0, 1):
            with patch.object(winreg, "OpenKey") as opened, patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), patch.object(winreg, "EnumValue", return_value=("IsSlowLink", value, winreg.REG_DWORD)), redirect_stdout(io.StringIO()) as output:
                opened.side_effect = [opened.return_value, FileNotFoundError()]
                script.verify_no_policy_history()
            for text in ("IsSlowLink", "REG_DWORD", f"data={value}", "METADATA"):
                self.assertIn(text, output.getvalue())

    def test_unknown_metadata_and_actual_gpo_values_remain_blocked(self):
        for entry in (("GPOName", "{12345678-1234-1234-1234-123456789abc}", winreg.REG_SZ),
                      ("DSPath", "LDAP://domain/policy", winreg.REG_SZ),
                      ("UnknownValue", 0, winreg.REG_DWORD),
                      ("IsSlowLink", "0", winreg.REG_SZ),
                      ("IsSlowLink", 2, winreg.REG_DWORD)):
            with self.subTest(entry=entry), patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), patch.object(winreg, "EnumValue", return_value=entry), redirect_stdout(io.StringIO()), self.assertRaises(script.EnvironmentDiagnosticError):
                script.verify_no_policy_history()

    def test_metadata_does_not_hide_gpo_subkeys_or_query_failure(self):
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(1, 1, 0)), patch.object(winreg, "EnumValue", return_value=("IsSlowLink", 0, winreg.REG_DWORD)), patch.object(winreg, "EnumKey", return_value="{domain-gpo-guid}"), redirect_stdout(io.StringIO()), self.assertRaises(script.EnvironmentDiagnosticError):
            script.verify_no_policy_history()
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), patch.object(winreg, "EnumValue", side_effect=PermissionError), redirect_stdout(io.StringIO()), self.assertRaises(PermissionError):
            script.verify_no_policy_history()

    def test_policy_overdue_zero_is_not_assumed_safe(self):
        # 실환경 값이 0이어도 의미를 입증할 근거 없이 허용하지 않는다.
        info = {**self.info, "gpos": [{"id": "LocalGPO"}]}
        for entry in (("PolicyOverdue", 0, winreg.REG_DWORD), ("PolicyOverdue", 1, winreg.REG_DWORD), ("PolicyOverdue", "0", winreg.REG_SZ)):
            with self.subTest(entry=entry), patch.object(script, "collect_environment", return_value=info), patch.object(script, "system_executable", return_value="C:/Windows/System32/gpresult.exe"), patch.object(script, "verify_local_gpo_files"), patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), patch.object(winreg, "EnumValue", return_value=entry), redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(script.EnvironmentDiagnosticError) as error:
                    script.require_local_policy()
                self.assertEqual(error.exception.reason_code, "POLICY_HISTORY_FOUND")
                self.assertIn("PolicyOverdue", output.getvalue())
                self.assertIn("HISTORY_OR_UNKNOWN", output.getvalue())

    def test_policy_overdue_additional_values_subkeys_and_read_failure_blocked(self):
        for subkeys, entries in ((0, [("PolicyOverdue", 0, winreg.REG_DWORD), ("IsSlowLink", 0, winreg.REG_DWORD)]), (1, [("PolicyOverdue", 0, winreg.REG_DWORD)])):
            with self.subTest(subkeys=subkeys), patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(subkeys, len(entries), 0)), patch.object(winreg, "EnumValue", side_effect=entries), patch.object(winreg, "EnumKey", return_value="{domain-gpo-guid}"), redirect_stdout(io.StringIO()), self.assertRaises(script.EnvironmentDiagnosticError):
                script.verify_no_policy_history()
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), patch.object(winreg, "EnumValue", side_effect=PermissionError), redirect_stdout(io.StringIO()), self.assertRaises(PermissionError):
            script.verify_no_policy_history()

    @patch.object(script, "diagnose_live_gpo", new=lambda: None)
    def test_policy_overdue_diagnostic_failure_never_enters_mutating_path(self):
        # 화면 요약만으로는 정책 이벤트의 동일 처리 세션을 검증할 수 없다.
        info = {**self.info, "gpos": [{"id": "LocalGPO", "version": 0}]}
        with patch.object(script, "_is_administrator", return_value=True), patch.object(script, "collect_environment", return_value=info), patch.object(script, "system_executable", return_value="C:/Windows/System32/gpresult.exe"), patch.object(script, "verify_local_gpo_files"), patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 0)), patch.object(winreg, "EnumValue", return_value=("PolicyOverdue", 0, winreg.REG_DWORD)), patch.object(script, "get_action") as action, patch.object(script, "prepare_fail") as prepare, patch.object(script, "collect_check") as check, patch("builtins.input") as approval, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(script.main(["--code", "W-07", "--diagnose-env"]), 1)
            for unused in (action, prepare, check, approval):
                unused.assert_not_called()
            for message in ("PolicyOverdue", "REG_DWORD", "data=0", "POLICY_HISTORY_FOUND", "[SKIP]"):
                self.assertIn(message, output.getvalue())

    def test_local_rsop_object_count_is_not_applied_domain_gpo_count(self):
        self.info["gpos"] = [{"id": "LocalGPO", "enabled": True, "access_denied": False,
                              "filter_allowed": True, "version": 0}]
        with redirect_stdout(io.StringIO()) as output:
            self.verify(self.info)
        self.assertIn("RSOP 객체 개수=1", output.getvalue())
        self.assertIn("적용 GPO 개수=0", output.getvalue())
        self.assertIn('"id": "LocalGPO"', output.getvalue())
