import unittest
from unittest.mock import patch
import winreg

from agent.checks.common import NativeWindowsReadOnlyApi
from agent.windows_checks import collect_check


class Policy485359Tests(unittest.TestCase):
    def setUp(self):
        self.api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)

    def test_w48_correct_path_type_and_decision(self):
        for value, status in [(0, "PASS"), (1, "FAIL"), (2, "UNABLE")]:
            with patch.object(winreg, "OpenKey") as opened, patch.object(
                winreg, "QueryValueEx", return_value=(value, winreg.REG_DWORD)
            ):
                self.assertEqual(collect_check("W-48", self.api).status, status)
                self.assertEqual(opened.call_args.args[1],
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                self.assertTrue(opened.call_args.args[3] & winreg.KEY_WOW64_64KEY)
        with patch.object(winreg, "OpenKey"), patch.object(
            winreg, "QueryValueEx", return_value=("0", winreg.REG_SZ)
        ):
            self.assertEqual(collect_check("W-48", self.api).status, "UNABLE")

    def test_missing_and_access_denied_do_not_assume_defaults(self):
        for code in ("W-48", "W-53", "W-59"):
            for error in (FileNotFoundError(), PermissionError()):
                with self.subTest(code=code, error=type(error)), patch.object(
                    winreg, "OpenKey", side_effect=error
                ):
                    self.assertEqual(collect_check(code, self.api).status, "UNABLE")

    def test_w53_and_w59_existing_registry_collection(self):
        for code, name, value, kind, status, path in [
            ("W-53", "AllocateDASD", "0", winreg.REG_SZ, "PASS",
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            ("W-53", "AllocateDASD", "1", winreg.REG_SZ, "FAIL",
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            ("W-59", "LmCompatibilityLevel", 3, winreg.REG_DWORD, "PASS",
             r"SYSTEM\CurrentControlSet\Control\Lsa"),
            ("W-59", "LmCompatibilityLevel", 2, winreg.REG_DWORD, "FAIL",
             r"SYSTEM\CurrentControlSet\Control\Lsa"),
        ]:
            with self.subTest(code=code, value=value), patch.object(winreg, "OpenKey") as opened, patch.object(
                winreg, "QueryValueEx", return_value=(value, kind)
            ) as queried:
                self.assertEqual(collect_check(code, self.api).status, status)
                self.assertEqual(opened.call_args.args[1], path)
                self.assertEqual(queried.call_args.args[1], name)
