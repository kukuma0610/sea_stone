import unittest
from unittest.mock import patch, MagicMock
import winreg

from agent.checks.common import NativeWindowsReadOnlyApi, WindowsApiUnavailable, _parse_target_user_right
from agent.windows_checks import collect_check


class TargetPolicyTests(unittest.TestCase):
    def setUp(self):
        self.api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)

    def test_registry_policies_actual_dword_and_missing(self):
        cases = [
            ("W-07", "EveryoneIncludesAnonymous", 0, 1),
            ("W-13", "LimitBlankPasswordUse", 1, 0),
            ("W-15", "ForceKeyProtection", 2, 1),
        ]
        for code, name, good, bad in cases:
            for value, expected in [(good, "PASS"), (bad, "FAIL")]:
                with self.subTest(code=code, value=value), patch.object(winreg, "OpenKey") as opened, patch.object(
                    winreg, "QueryValueEx", return_value=(value, winreg.REG_DWORD)
                ) as queried:
                    result = collect_check(code, self.api)
                    self.assertEqual(result.status, expected)
                    self.assertEqual(queried.call_args.args[1], name)
                    self.assertTrue(opened.call_args.args[3] & winreg.KEY_WOW64_64KEY)
            for failure in (FileNotFoundError(), PermissionError()):
                with patch.object(winreg, "OpenKey", side_effect=failure):
                    result = collect_check(code, self.api)
                    self.assertEqual(result.status, "UNABLE")
                    self.assertTrue(result.error_reason)
            with patch.object(winreg, "OpenKey"), patch.object(
                winreg, "QueryValueEx", return_value=("1", winreg.REG_SZ)
            ):
                self.assertEqual(collect_check(code, self.api).status, "UNABLE")

    def test_w11_and_w49_request_user_rights_area(self):
        for code, key in [("W-11", "SeInteractiveLogonRight"), ("W-49", "SeRemoteShutdownPrivilege")]:
            text = f"[Privilege Rights]\r\n{key} = *S-1-5-32-544\r\n"
            with patch.object(self.api, "_export_security_policy", return_value=text) as export:
                self.assertEqual(collect_check(code, self.api).status, "PASS")
                export.assert_called_once_with("USER_RIGHTS")
            with patch.object(self.api, "_export_security_policy", return_value="[Privilege Rights]\r\n"):
                self.assertEqual(collect_check(code, self.api).status, "UNABLE")

    def test_right_parser_empty_value_does_not_consume_next_line(self):
        for key in ("SeInteractiveLogonRight", "SeRemoteShutdownPrivilege"):
            text = f"[Privilege Rights]\r\n{key} = \r\nOtherRight = *S-1-5-32-544\r\n"
            self.assertEqual(_parse_target_user_right(text, key), [])
            with self.assertRaises(WindowsApiUnavailable):
                _parse_target_user_right(f"[Other Section]\n{key}=*S-1-5-32-544", key)

    def test_export_selects_area_and_preserves_default(self):
        from pathlib import Path
        from types import SimpleNamespace

        def export_command(args, **kwargs):
            Path(args[args.index("/cfg") + 1]).write_bytes("[Privilege Rights]\r\n".encode("utf-16"))
            return SimpleNamespace(returncode=0)

        with patch("agent.checks.common.subprocess.run", side_effect=export_command) as run:
            self.api._export_security_policy("USER_RIGHTS")
            self.assertEqual(run.call_args.args[0][-2:], ["USER_RIGHTS", "/quiet"])
            self.api._export_security_policy()
            self.assertEqual(run.call_args.args[0][-2:], ["SECURITYPOLICY", "/quiet"])
