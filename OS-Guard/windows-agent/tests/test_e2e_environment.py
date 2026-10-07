from copy import deepcopy
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
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(1, 0, 0)):
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
