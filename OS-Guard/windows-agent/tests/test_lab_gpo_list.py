from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch
import winreg

from scripts import lab_hardening_policy as policy

STATE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List"


class GpoListTests(unittest.TestCase):
    def test_empty_key_or_exact_empty_default_is_not_policy_content(self):
        for info, entry in (((0, 0, 1), None), ((0, 1, 1), ("", "", winreg.REG_SZ))):
            with self.subTest(info=info), patch.object(winreg, "OpenKey"), \
                    patch.object(winreg, "QueryInfoKey", return_value=info), \
                    patch.object(winreg, "EnumValue", return_value=entry) as enum, redirect_stdout(io.StringIO()):
                policy.verify_gpo_list_state(winreg, STATE)
                if entry is None: enum.assert_not_called()

    def test_named_zero_nonempty_default_and_other_types_remain_blocked(self):
        for entry in (("Version", 0, winreg.REG_DWORD), ("PolicyOverdue", 0, winreg.REG_DWORD),
                      ("", 0, winreg.REG_DWORD), ("", "LocalGPO", winreg.REG_SZ),
                      ("", "", winreg.REG_EXPAND_SZ), ("GPOID", "LocalGPO", winreg.REG_SZ)):
            with self.subTest(entry=entry), patch.object(winreg, "OpenKey"), \
                    patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 1)), \
                    patch.object(winreg, "EnumValue", return_value=entry), redirect_stdout(io.StringIO()), \
                    self.assertRaises(policy.LabRejected) as caught:
                policy.verify_gpo_list_state(winreg, STATE)
            self.assertEqual(str(caught.exception), "LAB_GPO_LIST_NOT_EMPTY")

    def test_local_object_subkey_is_diagnostic_not_automatic_application_or_safety(self):
        output = io.StringIO()
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", side_effect=[(1, 0, 1), (0, 1, 1)]), \
                patch.object(winreg, "EnumKey", return_value="0"), \
                patch.object(winreg, "EnumValue", return_value=("DsPath", "LocalGPO", winreg.REG_SZ)), \
                redirect_stdout(output), self.assertRaises(policy.LabRejected):
            policy.verify_gpo_list_state(winreg, STATE)
        self.assertIn("LocalGPO", output.getvalue())
        self.assertIn("적용 GPO 수가 아닌 Registry 객체 수", output.getvalue())

    def test_missing_key_is_distinct_from_read_failure_or_disappearing_value(self):
        with patch.object(winreg, "OpenKey", side_effect=FileNotFoundError), redirect_stdout(io.StringIO()):
            policy.verify_gpo_list_state(winreg, STATE)
        with patch.object(winreg, "OpenKey", side_effect=PermissionError), self.assertRaises(PermissionError):
            policy.verify_gpo_list_state(winreg, STATE)
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 1)), \
                patch.object(winreg, "EnumValue", side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
            policy.verify_gpo_list_state(winreg, STATE)

    def test_state_change_during_query_cannot_be_allowed(self):
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", side_effect=[(0, 0, 1), (1, 0, 2)]), \
                self.assertRaises(policy.LabRejected) as caught:
            policy.verify_gpo_list_state(winreg, STATE)
        self.assertEqual(str(caught.exception), "LAB_GPO_LIST_CHANGED_DURING_QUERY")

    def test_failed_diagnostic_cannot_convert_nonempty_key_to_pass(self):
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(1, 0, 1)), \
                patch.object(winreg, "EnumKey", side_effect=PermissionError), redirect_stdout(io.StringIO()), \
                self.assertRaises(policy.LabRejected) as caught:
            policy.verify_gpo_list_state(winreg, STATE)
        self.assertEqual(str(caught.exception), "LAB_GPO_LIST_NOT_EMPTY")

    def test_unknown_strings_are_masked_in_diagnostic(self):
        output = io.StringIO()
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", return_value=(0, 1, 1)), \
                patch.object(winreg, "EnumValue", return_value=("DisplayName", "private-domain-and-user", winreg.REG_SZ)), \
                redirect_stdout(output), self.assertRaises(policy.LabRejected):
            policy.verify_gpo_list_state(winreg, STATE)
        self.assertNotIn("private-domain-and-user", output.getvalue())
        self.assertIn("[MASKED]", output.getvalue())
