from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch
import winreg

from scripts import lab_hardening_policy as policy

STATE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List"


class GpoListTests(unittest.TestCase):
    def local_entries(self):
        return [(name, value, winreg.REG_DWORD) for name, value in
                (("Version", 0), ("WQLFilterPass", 1), ("AccessDenied", 0), ("GPO-Disabled", 0), ("Options", 0))] + [
                    ("GPOID", "Local Group Policy", winreg.REG_SZ), ("SOM", "Local", winreg.REG_SZ),
                    ("DisplayName", "Local Group Policy", winreg.REG_SZ), ("WQL-Id", "", winreg.REG_SZ)]

    def check_local(self, entries, child_info=None):
        child_info = child_info or (0, len(entries), 1)
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "EnumKey", return_value="0"), \
                patch.object(winreg, "QueryInfoKey", side_effect=[(1, 0, 1), child_info, child_info, (1, 0, 1)]), \
                patch.object(winreg, "EnumValue", side_effect=entries), redirect_stdout(io.StringIO()), \
                patch.object(policy, "describe_gpo_list"):
            policy.verify_gpo_list_state(winreg, STATE)

    def test_measured_version_zero_local_object_allowed(self):
        self.check_local(self.local_entries())

    def test_every_changed_local_field_or_type_is_blocked(self):
        original = self.local_entries()
        for index, (name, value, kind) in enumerate(original):
            for replacement in ((name, value + 1 if type(value) is int else value + "x", kind),
                                (name, value, winreg.REG_BINARY)):
                entries = original.copy()
                entries[index] = replacement
                with self.subTest(field=name, replacement=replacement), self.assertRaises(policy.LabRejected):
                    self.check_local(entries)

    def test_external_gpo_and_duplicate_identity_are_blocked(self):
        entries = self.local_entries()
        entries[5] = ("GPOID", "{11111111-1111-1111-1111-111111111111}", winreg.REG_SZ)
        with self.assertRaises(policy.LabRejected):
            self.check_local(entries)
        entries = self.local_entries()
        entries[-1] = entries[0]
        with self.assertRaises(policy.LabRejected):
            self.check_local(entries)

    def test_extra_values_or_nested_policy_objects_are_blocked(self):
        for info in ((0, 10, 1), (1, 9, 1)):
            with self.subTest(info=info), self.assertRaises(policy.LabRejected):
                self.check_local(self.local_entries(), info)

    def test_local_object_query_failure_is_not_allowed(self):
        with patch.object(winreg, "EnumKey", return_value="0"), patch.object(winreg, "OpenKey", side_effect=PermissionError), self.assertRaises(PermissionError):
            policy.verified_empty_local_gpo_object(winreg, object(), (1, 0, 1))

    def test_additional_gpo_or_unknown_child_name_remains_blocked(self):
        for info, name in (((2, 0, 1), "0"), ((1, 0, 1), "external")):
            with self.subTest(info=info, name=name), patch.object(winreg, "EnumKey", return_value=name):
                self.assertFalse(policy.verified_empty_local_gpo_object(winreg, object(), info))

    def test_local_child_changed_during_read_is_rejected(self):
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "EnumKey", return_value="0"), \
                patch.object(winreg, "QueryInfoKey", side_effect=[(0, 9, 1), (0, 9, 2)]), \
                patch.object(winreg, "EnumValue", side_effect=self.local_entries()), \
                self.assertRaises(policy.LabRejected) as caught:
            policy.verified_empty_local_gpo_object(winreg, object(), (1, 0, 1))
        self.assertEqual(str(caught.exception), "LAB_GPO_LIST_CHANGED_DURING_QUERY")

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
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryInfoKey", side_effect=[(1, 0, 1), (0, 1, 1), (0, 1, 1)]), \
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
                patch.object(policy, "verified_empty_local_gpo_object", return_value=False), patch.object(winreg, "EnumKey", side_effect=PermissionError), redirect_stdout(io.StringIO()), \
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
