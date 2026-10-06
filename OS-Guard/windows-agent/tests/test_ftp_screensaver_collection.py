import ctypes
import unittest
from unittest.mock import Mock, patch
import winreg

from agent.checks.common import NativeWindowsReadOnlyApi, WindowsApiUnavailable
from agent.windows_checks import collect_check


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)

    def test_ftp_unused_and_running_without_sites(self):
        for running in (False, True):
            with patch.object(self.api, "_run_powershell_json", return_value=[
                {"service_running": running, "sites": []}
            ]):
                inventory = self.api.ftp_check_inventory()
                self.assertEqual(inventory["collection_state"], "RUNNING_NO_SITES" if running else "UNUSED")
                self.assertEqual(collect_check("W-21", self.api).status, "UNABLE" if running else "PASS")
                for code in ("W-22", "W-24"):
                    result = collect_check(code, self.api)
                    self.assertEqual(result.status, "UNABLE")
                    self.assertTrue(result.error_reason)

    def test_ftp_sites_success(self):
        site = {"ssl_control_policy": "SslRequire", "ssl_data_policy": "SslRequire",
                "everyone_acl": False, "broad_authorization": False,
                "ip_allow_unlisted": False, "ip_allow_count": 1}
        with patch.object(self.api, "_run_powershell_json", return_value=[
            {"service_running": True, "sites": [site]}
        ]):
            self.assertEqual(self.api.ftp_check_inventory()["collection_state"], "SITES_COLLECTED")
            for code in ("W-21", "W-22", "W-24"):
                self.assertEqual(collect_check(code, self.api).status, "PASS")

    def test_ftp_module_query_permission_errors(self):
        for error in ("FTP_MODULE_QUERY_FAILED", "FTP_FTP_QUERY_FAILED", "FTP_ACCESS_DENIED"):
            with patch.object(self.api, "_run_powershell_json", return_value=[
                {"collection_state": "ERROR", "error_reason": error}
            ]):
                for code in ("W-21", "W-22", "W-24"):
                    result = collect_check(code, self.api)
                    self.assertEqual(result.status, "UNABLE")
                    self.assertEqual(result.error_reason, error)

    def test_ftp_command_failure_and_invalid_output(self):
        with patch.object(self.api, "_run_powershell_json", side_effect=WindowsApiUnavailable("command failed")):
            for code in ("W-21", "W-22", "W-24"):
                self.assertEqual(collect_check(code, self.api).error_reason, "command failed")
        for data in ([], [{}], [{"service_running": False, "sites": None}]):
            with patch.object(self.api, "_run_powershell_json", return_value=data):
                self.assertEqual(collect_check("W-21", self.api).status, "UNABLE")

    def test_legacy_ftp_caller_is_unchanged(self):
        with patch.object(self.api, "_run_powershell_json", return_value=[{"sites": []}]) as run:
            self.assertEqual(self.api.ftp_inventory(), {"sites": []})
            self.assertNotIn("$stage", run.call_args.args[0])
            with self.assertRaises(WindowsApiUnavailable):
                self.api.ftp_check_inventory()
            self.assertIn("$ErrorActionPreference = 'Stop'", run.call_args.args[0])

    def test_registry_absence_is_separate_from_live_value(self):
        effective = {k: {"state": "error", "value": None, "error_reason": "SPI_FAILED"}
                     for k in ("enabled", "password_protected", "timeout_seconds")}
        with patch.object(winreg, "OpenKey", side_effect=FileNotFoundError()), patch.object(
            self.api, "_screen_saver_effective_values", return_value=effective
        ):
            result = collect_check("W-47", self.api)
            self.assertEqual(result.status, "UNABLE")
            self.assertIsNone(result.current_value["password_protected"])
            self.assertEqual(result.current_value["sources"]["user_preferences"]["enabled"]["state"], "absent")
            self.assertIn("SPI_FAILED", result.error_reason)

    def test_machine_user_sources_do_not_override_live_values(self):
        effective = {"enabled": {"state": "present", "value": True},
                     "password_protected": {"state": "present", "value": False},
                     "timeout_seconds": {"state": "error", "value": None, "error_reason": "SPI_TIMEOUT_FAILED"}}
        with patch.object(winreg, "OpenKey"), patch.object(winreg, "QueryValueEx", return_value=("1", winreg.REG_SZ)), patch.object(
            self.api, "_screen_saver_effective_values", return_value=effective
        ):
            result = collect_check("W-47", self.api)
            self.assertEqual(result.status, "FAIL")
            self.assertTrue(result.manual_review_required)
            for scope in ("machine_policy", "user_policy", "user_preferences"):
                self.assertTrue(result.current_value["sources"][scope]["password_protected"]["value"])
            self.assertFalse(result.current_value["password_protected"])

    def test_registry_permission_failure_preserved(self):
        effective = {k: {"state": "error", "value": None, "error_reason": "SPI_FAILED"}
                     for k in ("enabled", "password_protected", "timeout_seconds")}
        with patch.object(winreg, "OpenKey", side_effect=PermissionError()), patch.object(
            self.api, "_screen_saver_effective_values", return_value=effective
        ):
            result = collect_check("W-47", self.api)
            self.assertEqual(result.status, "UNABLE")
            self.assertEqual(result.current_value["sources"]["machine_policy"]["enabled"]["state"], "error")

    def test_live_spi_reads_only_get_actions_and_preserves_failure(self):
        actions = []
        def query(action, parameter, pointer, flags):
            actions.append(action)
            self.assertEqual((parameter, flags), (0, 0))
            if action == 0x000E:
                return 0
            pointer._obj.value = 1 if action == 0x0010 else 0
            return 1
        dll = Mock()
        dll.SystemParametersInfoW.side_effect = query
        with patch.object(ctypes, "WinDLL", return_value=dll), patch.object(ctypes, "get_last_error", return_value=5):
            values = self.api._screen_saver_effective_values()
        self.assertEqual(actions, [0x0010, 0x0076, 0x000E])
        self.assertFalse(values["password_protected"]["value"])
        self.assertIsNone(values["timeout_seconds"]["value"])
        self.assertIn(":5", values["timeout_seconds"]["error_reason"])

    def test_generated_ftp_powershell_with_stubbed_windows_commands(self):
        # Execute the actual generated script, but shadow every Windows query.
        with patch.object(self.api, "_run_powershell_json", return_value=[
            {"service_running": True, "sites": []}
        ]) as run:
            self.api.ftp_check_inventory()
            script = run.call_args.args[0]
        for installed, running, module, query_error, expected in [
            (False, False, False, False, "UNUSED"),
            (True, False, False, False, "ERROR"),
            (True, False, True, False, None),
            (True, True, False, False, "ERROR"),
            (True, True, True, False, None),
            (True, True, True, True, "ERROR"),
        ]:
            prefix = """
function Get-Service { [pscustomobject]@{ Name='FTPSVC'; Status='STATUS' } }
function Get-Module { MODULE }
function Import-Module {}
function Get-Website { QUERY }
""".replace("STATUS", "Running" if running else "Stopped").replace(
                "MODULE", "'WebAdministration'" if module else ""
            ).replace("QUERY", "throw 'synthetic query error'" if query_error else "")
            if not installed:
                prefix = prefix.replace(
                    "[pscustomobject]@{ Name='FTPSVC'; Status='Stopped' }", ""
                )
            rows = self.api._run_powershell_json(prefix + script)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].get("collection_state"), expected)
            if expected != "ERROR":
                self.assertEqual(rows[0]["sites"], [])
                self.assertEqual(rows[0]["service_running"], running)
