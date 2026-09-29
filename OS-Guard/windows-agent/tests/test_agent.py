import tempfile
import unittest
from pathlib import Path

from agent.client import AgentClient, CommunicationError, HttpsTransport, MockApi
from agent.identity import AgentIdentity
from agent.inventory import collect_inventory
from agent.results import WindowsEvidence, build_mock_check_result
from agent.tasks import InvalidTask
from agent.windows_checks import (
    KISA_SOURCES,
    WINDOWS_CHECKS,
    _parse_dont_display_last_username,
    _parse_registry_dword,
    _parse_reversible_password_encryption,
    _parse_security_policy_list,
    _parse_security_policy_flag,
    collect_check,
)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.identity = AgentIdentity.load_or_create(Path(self.temp_dir.name) / "identity.json")
        self.mock = MockApi()
        self.client = AgentClient(self.identity, self.mock)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_inventory_is_read_only_shape(self):
        inventory = collect_inventory()
        self.assertIn("family", inventory)
        self.assertIn("version", inventory)
        self.assertIn("hostname", inventory)

    def test_enroll_and_heartbeat_contract(self):
        enrollment = self.client.enroll()
        self.assertEqual(enrollment["server_id"], "srv-win-mock")
        self.client.heartbeat()
        self.assertEqual(self.mock.last_heartbeat["agent_id"], self.identity.agent_id)
        self.assertEqual(self.mock.last_heartbeat["agent_version"], self.identity.version)
        self.assertEqual(self.mock.last_heartbeat["module_version"], "windows-agent-mock-0.1.0")

    def test_only_check_task_is_claimed(self):
        self.mock.tasks.append({"action": "CHECK", "scan_scope": "PARTIAL", "item_ids": ["W-01"]})
        self.assertEqual(self.client.claim_check()["action"], "CHECK")

    def test_command_task_is_rejected(self):
        self.mock.tasks.append({"action": "CHECK", "scan_scope": "FULL", "command": "whoami"})
        with self.assertRaises(InvalidTask):
            self.client.claim_check()

    def test_non_check_task_is_rejected(self):
        self.mock.tasks.append({"action": "HARDEN", "scan_scope": "FULL"})
        with self.assertRaises(InvalidTask):
            self.client.claim_check()

    def test_result_is_received_and_duplicate_is_not_stored_twice(self):
        task = {
            "action": "CHECK",
            "scan_scope": "PARTIAL",
            "item_ids": ["W-01"],
            "job_id": "job-win-mock",
            "scan_run_id": "run-win-mock",
            "attempt_id": "attempt-win-mock",
        }
        result = build_mock_check_result(self.identity, task)
        first = self.client.submit_check_result(result)
        second = self.client.submit_check_result(result)
        self.assertEqual(first["accepted_ids"], [result.result_id])
        self.assertEqual(second["duplicate_ids"], [result.result_id])
        self.assertEqual(len(self.mock.received_results), 1)
        self.assertEqual(self.mock.received_results[result.result_id]["item_id"], "W-01")

    def test_claim_executes_collectors_submits_results_and_continues_after_error(self):
        class Api:
            def accounts(self):
                raise ValueError("simulated malformed account data")
            def lockout_threshold(self):
                return 5

        self.mock.tasks.append({
            "action": "CHECK",
            "scan_scope": "PARTIAL",
            "item_ids": ["W-02", "W-04"],
            "server_id": "srv-integrated",
            "job_id": "job-integrated",
            "scan_run_id": "run-integrated",
            "attempt_id": "attempt-integrated",
            "criteria_snapshot_id": "criteria-integrated",
        })
        responses = self.client.claim_execute_submit_checks(Api())
        self.assertEqual(len(responses), 2)
        payloads = {payload["item_id"]: payload for payload in self.mock.received_results.values()}
        self.assertEqual(payloads["W-02"]["status"], "UNABLE")
        self.assertIn("error_reason", payloads["W-02"]["error"])
        self.assertEqual(payloads["W-04"]["status"], "PASS")
        self.assertEqual(payloads["W-04"]["server_id"], "srv-integrated")
        self.assertEqual(payloads["W-04"]["criteria_snapshot_id"], "criteria-integrated")

    def test_check_execution_rejects_missing_required_identifiers(self):
        self.mock.tasks.append({
            "action": "CHECK",
            "scan_scope": "PARTIAL",
            "item_ids": ["W-04"],
            "job_id": "job-missing-identifiers",
            "scan_run_id": "run-missing-identifiers",
            "attempt_id": "attempt-missing-identifiers",
        })
        with self.assertRaises(InvalidTask):
            self.client.claim_execute_submit_checks()
        self.assertEqual(self.mock.received_results, {})

    def test_manual_review_is_preserved_in_existing_current_value(self):
        class Api:
            def accounts(self):
                return [{"name": "Administrator", "user_id": 500, "disabled": False}]

        self.mock.tasks.append({
            "action": "CHECK",
            "scan_scope": "PARTIAL",
            "item_ids": ["W-01"],
            "server_id": "srv-manual-review",
            "job_id": "job-manual-review",
            "scan_run_id": "run-manual-review",
            "attempt_id": "attempt-manual-review",
            "criteria_snapshot_id": "criteria-manual-review",
        })
        self.client.claim_execute_submit_checks(Api())
        payload = next(iter(self.mock.received_results.values()))
        self.assertEqual(payload["status"], "UNABLE")
        self.assertTrue(payload["current_value"]["manual_review_required"])

    def test_evidence_metadata_shape_is_redacted(self):
        evidence = WindowsEvidence(
            evidence_id="ev-win-mock",
            server_id="srv-win-mock",
            scan_run_id="run-win-mock",
            item_id="W-01",
            collector_id="W-01.collect.mock",
            captured_at="2026-09-22T00:00:00Z",
        ).to_payload()
        self.assertTrue(evidence["redacted"])
        self.assertEqual(evidence["media_type"], "application/json")

    def test_communication_failure_is_sanitized(self):
        class FailingTransport:
            def post(self, path, payload, headers):
                raise OSError("simulated network failure")

        failing = AgentClient(self.identity, FailingTransport())
        with self.assertRaises(CommunicationError):
            failing.heartbeat()

    def test_real_transport_rejects_mock_result_values_before_network(self):
        transport = HttpsTransport("https://central.example.invalid")
        payload = {
            "auto_stage_state": "MOCK_ONLY",
            "server_id": "srv-real",
            "criteria_snapshot_id": "criteria-real",
        }
        with self.assertRaises(ValueError):
            transport.post("/agent-api/v2/tasks/job-1/results", payload, {})

    def test_invalid_claim_response_is_rejected(self):
        self.mock.tasks.append({"scan_scope": "FULL"})
        with self.assertRaises(InvalidTask):
            self.client.claim_check()

    def test_all_documented_windows_items_are_registered(self):
        self.assertEqual(len(WINDOWS_CHECKS), 64)
        self.assertEqual(set(WINDOWS_CHECKS), {f"W-{i:02d}" for i in range(1, 65)})

    def test_all_windows_checks_have_kisa_sources(self):
        self.assertEqual(set(KISA_SOURCES), set(WINDOWS_CHECKS))

    def test_kisa_w01_to_w04_with_read_only_mock_api(self):
        class Api:
            def accounts(self):
                return [{"name": "RenamedAdmin", "user_id": 500, "disabled": False}, {"name": "Guest", "user_id": 501, "disabled": True}]
            def lockout_threshold(self):
                return 5

        api = Api()
        self.assertEqual(collect_check("W-01", api).status, "PASS")
        self.assertEqual(collect_check("W-02", api).status, "PASS")
        self.assertEqual(collect_check("W-03", api).status, "UNABLE")
        self.assertEqual(collect_check("W-04", api).status, "PASS")

    def test_kisa_w01_manual_and_w03_masked_evidence(self):
        class Api:
            def accounts(self):
                return [{"name": "Administrator", "user_id": 500, "disabled": False}, {"name": "SensitiveUser", "user_id": 1001, "disabled": False}]

        w01 = collect_check("W-01", Api())
        w03 = collect_check("W-03", Api())
        self.assertEqual(w01.status, "UNABLE")
        self.assertTrue(w01.manual_review_required)
        self.assertNotIn("Administrator", str(w03.current_value))
        self.assertNotIn("SensitiveUser", str(w03.current_value))
        self.assertTrue(w03.manual_review_required)

    def test_kisa_w05_pass_fail_and_domain_unable(self):
        class Api:
            def __init__(self, enabled, domain=False):
                self.enabled = enabled
                self.domain = domain
            def reversible_password_encryption_enabled(self):
                return self.enabled
            def domain_joined(self):
                return self.domain

        self.assertEqual(collect_check("W-05", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-05", Api(True)).status, "FAIL")
        domain_result = collect_check("W-05", Api(False, True))
        self.assertEqual(domain_result.status, "UNABLE")
        self.assertTrue(domain_result.manual_review_required)

    def test_kisa_w05_security_policy_export_parser(self):
        self.assertFalse(_parse_reversible_password_encryption("[System Access]\nClearTextPassword = 0\n"))
        self.assertTrue(_parse_reversible_password_encryption("[System Access]\nClearTextPassword = 1\n"))

    def test_kisa_w02_and_w04_regression_failures(self):
        class Api:
            def accounts(self):
                return [{"name": "Guest", "user_id": 501, "disabled": False}]
            def lockout_threshold(self):
                return 6

        self.assertEqual(collect_check("W-02", Api()).status, "FAIL")
        self.assertEqual(collect_check("W-04", Api()).status, "FAIL")

    def test_w01_to_w05_share_result_shape(self):
        class Api:
            def accounts(self):
                return [{"name": "RenamedAdmin", "user_id": 500, "disabled": False}, {"name": "Guest", "user_id": 501, "disabled": True}]
            def lockout_threshold(self):
                return 5
            def reversible_password_encryption_enabled(self):
                return False
            def domain_joined(self):
                return False

        for item_id in ("W-01", "W-02", "W-03", "W-04", "W-05"):
            result = collect_check(item_id, Api())
            self.assertTrue(result.observed_at)
            self.assertIsInstance(result.current_value, dict)
            self.assertIsNotNone(result.source_page)
            self.assertTrue(result.evidence_redacted)

    def test_kisa_w06_pass_and_manual_review(self):
        class Api:
            def __init__(self, members):
                self.members = members
            def administrator_group_members(self):
                return self.members

        self.assertEqual(collect_check("W-06", Api(["SERVER\\Administrator"])).status, "PASS")
        manual = collect_check("W-06", Api(["SERVER\\Administrator", "DOMAIN\\SensitiveAdmin"]))
        self.assertEqual(manual.status, "UNABLE")
        self.assertTrue(manual.manual_review_required)
        self.assertNotIn("SensitiveAdmin", str(manual.current_value))

    def test_kisa_w07_w08_w10_pass_fail(self):
        class Api:
            def __init__(self, enabled=False, duration=3600, reset=3600):
                self.enabled = enabled
                self.duration = duration
                self.reset = reset
            def everyone_includes_anonymous(self):
                return self.enabled
            def lockout_policy(self):
                return {"threshold": 5, "duration_seconds": self.duration, "reset_seconds": self.reset}
            def dont_display_last_username(self):
                return self.enabled

        self.assertEqual(collect_check("W-07", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-07", Api(True)).status, "FAIL")
        self.assertEqual(collect_check("W-08", Api(duration=3600, reset=3600)).status, "PASS")
        self.assertEqual(collect_check("W-08", Api(duration=3599, reset=3600)).status, "FAIL")
        self.assertEqual(collect_check("W-10", Api(True)).status, "PASS")
        self.assertEqual(collect_check("W-10", Api(False)).status, "FAIL")

    def test_kisa_w07_and_w10_security_policy_parsers(self):
        self.assertFalse(_parse_security_policy_flag("EveryoneIncludesAnonymous = 0\n", "EveryoneIncludesAnonymous"))
        self.assertTrue(_parse_security_policy_flag("EveryoneIncludesAnonymous = 1\n", "EveryoneIncludesAnonymous"))
        path = "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName"
        self.assertTrue(_parse_dont_display_last_username(f"{path}=4,1\n"))
        self.assertFalse(_parse_dont_display_last_username(f"{path}=4,0\n"))

    def test_kisa_w09_password_policy_pass_fail(self):
        class Api:
            def __init__(self, minimum_length=8):
                self.minimum_length = minimum_length
            def password_policy(self):
                return {
                    "complexity_enabled": True,
                    "minimum_length": self.minimum_length,
                    "maximum_age_seconds": 90 * 86400,
                    "minimum_age_seconds": 86400,
                    "history_length": 4,
                }

        self.assertEqual(collect_check("W-09", Api()).status, "PASS")
        self.assertEqual(collect_check("W-09", Api(7)).status, "FAIL")

    def test_w06_to_w10_share_result_shape_and_no_unfounded_na(self):
        class Api:
            def administrator_group_members(self):
                return ["SERVER\\Administrator"]
            def everyone_includes_anonymous(self):
                return False
            def lockout_policy(self):
                return {"threshold": 5, "duration_seconds": 3600, "reset_seconds": 3600}
            def password_policy(self):
                return {"complexity_enabled": True, "minimum_length": 8, "maximum_age_seconds": 90 * 86400, "minimum_age_seconds": 86400, "history_length": 4}
            def dont_display_last_username(self):
                return True

        for item_id in ("W-06", "W-07", "W-08", "W-09", "W-10"):
            result = collect_check(item_id, Api())
            self.assertTrue(result.observed_at)
            self.assertIsNotNone(result.source_page)
            self.assertTrue(result.evidence_redacted)
            self.assertNotEqual(result.status, "NA")

    def test_kisa_w11_local_logon_pass_fail_and_masking(self):
        class Api:
            def __init__(self, principals):
                self.principals = principals
            def local_logon_principals(self):
                return self.principals

        passed = collect_check("W-11", Api(["BUILTIN_ADMINISTRATORS", "SERVER\\IUSR_WEB"]))
        failed = collect_check("W-11", Api(["BUILTIN_ADMINISTRATORS", "DOMAIN\\SensitiveUser"]))
        self.assertEqual(passed.status, "PASS")
        self.assertEqual(failed.status, "FAIL")
        self.assertNotIn("SensitiveUser", str(failed.current_value))

    def test_kisa_w12_w13_pass_fail(self):
        class Api:
            def __init__(self, enabled):
                self.enabled = enabled
            def anonymous_sid_name_translation_enabled(self):
                return self.enabled
            def blank_password_use_restricted(self):
                return self.enabled

        self.assertEqual(collect_check("W-12", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-12", Api(True)).status, "FAIL")
        self.assertEqual(collect_check("W-13", Api(True)).status, "PASS")
        self.assertEqual(collect_check("W-13", Api(False)).status, "FAIL")

    def test_kisa_w14_fail_or_manual_review(self):
        class Api:
            def __init__(self, members):
                self.members = members
            def remote_desktop_group_members(self):
                return self.members

        self.assertEqual(collect_check("W-14", Api([])).status, "FAIL")
        manual = collect_check("W-14", Api(["DOMAIN\\RemoteOperator"]))
        self.assertEqual(manual.status, "UNABLE")
        self.assertTrue(manual.manual_review_required)
        self.assertNotIn("RemoteOperator", str(manual.current_value))

    def test_kisa_w15_pass_fail_and_policy_parsers(self):
        class Api:
            def __init__(self, level):
                self.level = level
            def strong_key_protection_level(self):
                return self.level

        self.assertEqual(collect_check("W-15", Api(2)).status, "PASS")
        self.assertEqual(collect_check("W-15", Api(1)).status, "FAIL")
        policy = "SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-21-1\n"
        self.assertEqual(_parse_security_policy_list(policy, "SeInteractiveLogonRight"), ["*S-1-5-32-544", "*S-1-5-21-1"])
        path = r"MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection"
        self.assertEqual(_parse_registry_dword(f"{path}=4,2\n", path), 2)

    def test_w11_to_w15_share_result_shape_and_no_unfounded_na(self):
        class Api:
            def local_logon_principals(self):
                return ["BUILTIN_ADMINISTRATORS"]
            def anonymous_sid_name_translation_enabled(self):
                return False
            def blank_password_use_restricted(self):
                return True
            def remote_desktop_group_members(self):
                return ["DOMAIN\\RemoteOperator"]
            def strong_key_protection_level(self):
                return 2

        for item_id in ("W-11", "W-12", "W-13", "W-14", "W-15"):
            result = collect_check(item_id, Api())
            self.assertTrue(result.observed_at)
            self.assertIsNotNone(result.source_page)
            self.assertTrue(result.evidence_redacted)
            self.assertNotEqual(result.status, "NA")

    def test_kisa_w16_share_permissions_pass_fail(self):
        class Api:
            def __init__(self, everyone):
                self.everyone = everyone
            def shares(self):
                return [
                    {"name": "ADMIN$", "special": True, "everyone_allowed": True},
                    {"name": "Data", "special": False, "everyone_allowed": self.everyone},
                ]

        self.assertEqual(collect_check("W-16", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-16", Api(True)).status, "FAIL")

    def test_kisa_w17_default_shares_pass_fail(self):
        class Api:
            def __init__(self, autoshare, shares):
                self.autoshare = autoshare
                self._shares = shares
            def autoshare_server(self):
                return self.autoshare
            def shares(self):
                return self._shares

        self.assertEqual(collect_check("W-17", Api(0, [{"name": "IPC$"}])).status, "PASS")
        self.assertEqual(collect_check("W-17", Api(1, [{"name": "C$"}])).status, "FAIL")
        self.assertEqual(collect_check("W-17", Api(None, [])).status, "FAIL")

    def test_kisa_w18_and_w19_manual_boundaries(self):
        class ServicesApi:
            def running_services(self):
                return [{"name": "Spooler", "display_name": "Print Spooler", "status": "Running"}]
        w18 = collect_check("W-18", ServicesApi())
        self.assertEqual(w18.status, "UNABLE")
        self.assertTrue(w18.manual_review_required)

        class IisApi:
            def __init__(self, status):
                self.status = status
            def iis_services(self):
                return [] if self.status is None else [{"name": "W3SVC", "status": self.status}]
        self.assertEqual(collect_check("W-19", IisApi(None)).status, "PASS")
        self.assertEqual(collect_check("W-19", IisApi("Stopped")).status, "PASS")
        running = collect_check("W-19", IisApi("Running"))
        self.assertEqual(running.status, "UNABLE")
        self.assertTrue(running.manual_review_required)

    def test_kisa_w20_netbios_pass_fail_unable(self):
        class Api:
            def __init__(self, bindings):
                self.bindings = bindings
            def netbios_bindings(self):
                return self.bindings

        self.assertEqual(collect_check("W-20", Api([{"interface_index": 1, "tcpip_netbios_options": 2}])).status, "PASS")
        self.assertEqual(collect_check("W-20", Api([{"interface_index": 1, "tcpip_netbios_options": 0}])).status, "FAIL")
        self.assertEqual(collect_check("W-20", Api([])).status, "UNABLE")

    def test_w16_to_w20_share_result_shape_and_no_unfounded_na(self):
        class Api:
            def shares(self):
                return []
            def autoshare_server(self):
                return 0
            def running_services(self):
                return []
            def iis_services(self):
                return []
            def netbios_bindings(self):
                return [{"interface_index": 1, "tcpip_netbios_options": 2}]

        for item_id in ("W-16", "W-17", "W-18", "W-19", "W-20"):
            result = collect_check(item_id, Api())
            self.assertTrue(result.observed_at)
            self.assertIsNotNone(result.source_page)
            self.assertTrue(result.evidence_redacted)
            self.assertNotEqual(result.status, "NA")

    def test_kisa_w21_ftp_encryption_states(self):
        class Api:
            def __init__(self, running, sites):
                self.running = running
                self.sites = sites
            def ftp_inventory(self):
                return {"service_installed": True, "service_running": self.running, "sites": self.sites}

        secure = [{"ssl_control_policy": "SslRequire", "ssl_data_policy": "SslRequire"}]
        insecure = [{"ssl_control_policy": "SslAllow", "ssl_data_policy": "SslRequire"}]
        self.assertEqual(collect_check("W-21", Api(False, [])).status, "PASS")
        self.assertEqual(collect_check("W-21", Api(True, secure)).status, "PASS")
        self.assertEqual(collect_check("W-21", Api(True, insecure)).status, "FAIL")
        self.assertEqual(collect_check("W-21", Api(True, [])).status, "UNABLE")

    def test_kisa_w22_ftp_permissions_pass_fail_unable(self):
        class Api:
            def __init__(self, sites):
                self.sites = sites
            def ftp_inventory(self):
                return {"service_installed": bool(self.sites), "service_running": bool(self.sites), "sites": self.sites}

        safe = [{"everyone_acl": False, "broad_authorization": False}]
        unsafe = [{"everyone_acl": True, "broad_authorization": False}]
        self.assertEqual(collect_check("W-22", Api([])).status, "UNABLE")
        self.assertEqual(collect_check("W-22", Api(safe)).status, "PASS")
        self.assertEqual(collect_check("W-22", Api(unsafe)).status, "FAIL")

    def test_kisa_w23_anonymous_share_boundaries(self):
        class Api:
            def __init__(self, anonymous=False, shares=None, auxiliary=None):
                self.anonymous = anonymous
                self._shares = shares or []
                self.auxiliary = auxiliary or []
            def ftp_inventory(self):
                sites = [{"anonymous_enabled": self.anonymous}] if self.anonymous else []
                return {"service_installed": bool(sites), "service_running": bool(sites), "sites": sites}
            def shares(self):
                return self._shares
            def auxiliary_share_services(self):
                return self.auxiliary

        self.assertEqual(collect_check("W-23", Api(anonymous=True)).status, "FAIL")
        self.assertEqual(collect_check("W-23", Api(shares=[{"special": False}])).status, "FAIL")
        self.assertEqual(collect_check("W-23", Api()).status, "PASS")

    def test_kisa_w24_ftp_ip_restriction_pass_fail_unable(self):
        class Api:
            def __init__(self, sites):
                self.sites = sites
            def ftp_inventory(self):
                return {"service_installed": bool(self.sites), "service_running": bool(self.sites), "sites": self.sites}

        restricted = [{"ip_allow_unlisted": False, "ip_allow_count": 1}]
        open_site = [{"ip_allow_unlisted": True, "ip_allow_count": 0}]
        self.assertEqual(collect_check("W-24", Api([])).status, "UNABLE")
        self.assertEqual(collect_check("W-24", Api(restricted)).status, "PASS")
        self.assertEqual(collect_check("W-24", Api(open_site)).status, "FAIL")

    def test_kisa_w25_dns_zone_transfer_states(self):
        class Api:
            def __init__(self, running, transfer_types):
                self.running = running
                self.transfer_types = transfer_types
            def dns_inventory(self):
                return {
                    "service_installed": self.running,
                    "service_running": self.running,
                    "zones": [{"transfer_type": value} for value in self.transfer_types],
                }

        self.assertEqual(collect_check("W-25", Api(False, [])).status, "PASS")
        self.assertEqual(collect_check("W-25", Api(True, ["NoTransfer", "TransferToSecureServers"])).status, "PASS")
        self.assertEqual(collect_check("W-25", Api(True, ["TransferToAnyServer"])).status, "FAIL")
        self.assertEqual(collect_check("W-25", Api(True, ["Unknown"])).status, "UNABLE")

    def test_kisa_w26_server_version_states(self):
        class Api:
            def __init__(self, caption):
                self.caption = caption
            def windows_os_info(self):
                return {"caption": self.caption, "version": "10.0", "build_number": "20348"}

        self.assertEqual(collect_check("W-26", Api("Microsoft Windows Server 2022 Standard")).status, "PASS")
        manual = collect_check("W-26", Api("Microsoft Windows Server 2003"))
        self.assertEqual(manual.status, "UNABLE")
        self.assertTrue(manual.manual_review_required)

    def test_kisa_w27_latest_build_requires_manual_review(self):
        class Api:
            def windows_os_info(self):
                return {"caption": "Microsoft Windows Server 2022", "version": "10.0", "build_number": "20348"}

        result = collect_check("W-27", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertEqual(result.current_value["build_number"], "20348")

    def test_kisa_w28_rdp_encryption_states(self):
        class Api:
            def __init__(self, running, level):
                self.running = running
                self.level = level
            def rdp_inventory(self):
                return {"service_running": self.running, "minimum_encryption_level": self.level}

        self.assertEqual(collect_check("W-28", Api(False, None)).status, "PASS")
        self.assertEqual(collect_check("W-28", Api(True, 2)).status, "PASS")
        self.assertEqual(collect_check("W-28", Api(True, 1)).status, "FAIL")
        self.assertEqual(collect_check("W-28", Api(True, None)).status, "UNABLE")

    def test_kisa_w29_snmp_service_states(self):
        class Api:
            def __init__(self, running, count):
                self.running = running
                self.count = count
            def snmp_inventory(self):
                return {"service_running": self.running, "community_count": self.count, "default_community_count": 0}

        self.assertEqual(collect_check("W-29", Api(False, 0)).status, "PASS")
        self.assertEqual(collect_check("W-29", Api(True, 1)).status, "PASS")
        self.assertEqual(collect_check("W-29", Api(True, 0)).status, "FAIL")

    def test_kisa_w30_snmp_community_states(self):
        class Api:
            def __init__(self, running, count, default_count):
                self.running = running
                self.count = count
                self.default_count = default_count
            def snmp_inventory(self):
                return {"service_running": self.running, "community_count": self.count, "default_community_count": self.default_count}

        self.assertEqual(collect_check("W-30", Api(False, 0, 0)).status, "PASS")
        self.assertEqual(collect_check("W-30", Api(True, 1, 0)).status, "PASS")
        self.assertEqual(collect_check("W-30", Api(True, 1, 1)).status, "FAIL")
        self.assertEqual(collect_check("W-30", Api(True, 0, 0)).status, "UNABLE")

    def test_kisa_w31_snmp_access_control_states(self):
        class Api:
            def __init__(self, running, manager_count):
                self.running = running
                self.manager_count = manager_count
            def snmp_access_inventory(self):
                return {"service_running": self.running, "permitted_manager_count": self.manager_count}

        self.assertEqual(collect_check("W-31", Api(False, 0)).status, "PASS")
        self.assertEqual(collect_check("W-31", Api(True, 1)).status, "PASS")
        self.assertEqual(collect_check("W-31", Api(True, 0)).status, "FAIL")

    def test_kisa_w32_dns_dynamic_update_states(self):
        class Api:
            def __init__(self, running, updates):
                self.running = running
                self.updates = updates
            def dns_inventory(self):
                return {
                    "service_running": self.running,
                    "zones": [{"dynamic_update": value} for value in self.updates],
                }

        self.assertEqual(collect_check("W-32", Api(False, [])).status, "PASS")
        self.assertEqual(collect_check("W-32", Api(True, ["None"])).status, "PASS")
        self.assertEqual(collect_check("W-32", Api(True, ["Secure"])).status, "FAIL")
        self.assertEqual(collect_check("W-32", Api(True, [])).status, "UNABLE")

    def test_kisa_w33_banner_review_states(self):
        class Api:
            def __init__(self, services):
                self.services = services
            def banner_service_inventory(self):
                return self.services

        self.assertEqual(collect_check("W-33", Api([])).status, "PASS")
        manual = collect_check("W-33", Api([{"name": "W3SVC", "status": "Running"}]))
        self.assertEqual(manual.status, "UNABLE")
        self.assertTrue(manual.manual_review_required)

    def test_kisa_w34_server_2022_is_not_applicable(self):
        class Api:
            def __init__(self, caption):
                self.caption = caption
            def windows_os_info(self):
                return {"caption": self.caption, "version": "10.0", "build_number": "20348"}

        self.assertEqual(collect_check("W-34", Api("Microsoft Windows Server 2022 Standard")).status, "NA")
        self.assertEqual(collect_check("W-34", Api("Microsoft Windows Server 2012 R2")).status, "UNABLE")

    def test_kisa_w35_odbc_requires_manual_review(self):
        class Api:
            def odbc_inventory(self):
                return {"system_dsn_count": 2, "driver_count": 5, "system_dsn_names": ["SensitiveDsn"], "driver_names": ["SqlDriver"]}

        result = collect_check("W-35", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertNotIn("SensitiveDsn", result.current_value["system_dsns_masked"])

    def test_kisa_w36_remote_idle_timeout_states(self):
        class Api:
            def __init__(self, timeout):
                self.timeout = timeout
            def remote_idle_timeout_minutes(self):
                return self.timeout

        self.assertEqual(collect_check("W-36", Api(30)).status, "PASS")
        self.assertEqual(collect_check("W-36", Api(31)).status, "FAIL")
        self.assertEqual(collect_check("W-36", Api(None)).status, "FAIL")

    def test_kisa_w37_scheduled_tasks_require_manual_review(self):
        class Api:
            def scheduled_task_inventory(self):
                return {"task_count": 20, "non_microsoft_task_count": 2, "non_microsoft_task_identifiers": ["SensitiveTask"]}

        result = collect_check("W-37", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertEqual(result.current_value["non_microsoft_task_count"], 2)
        self.assertNotIn("SensitiveTask", result.current_value["non_microsoft_tasks_masked"])

    def test_kisa_w38_patch_process_requires_manual_review(self):
        class Api:
            def patch_inventory(self):
                return {"installed_hotfix_count": 12, "latest_installed_on": "2026-09-01"}

        result = collect_check("W-38", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertEqual(result.current_value["installed_hotfix_count"], 12)

    def test_kisa_w39_antivirus_currency_requires_manual_review(self):
        class Api:
            def antivirus_inventory(self):
                return {"defender_status_available": True, "antivirus_enabled": True, "signature_last_updated": "2026-09-28T00:00:00Z"}

        result = collect_check("W-39", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertTrue(result.current_value["antivirus_enabled"])

    def test_kisa_w40_audit_policy_pass_fail(self):
        class Api:
            def __init__(self, policy):
                self.policy = policy
            def audit_policy(self):
                return self.policy

        passing = {
            "AuditAccountManage": 2,
            "AuditAccountLogon": 3,
            "AuditPrivilegeUse": 3,
            "AuditDSAccess": 2,
            "AuditLogonEvents": 3,
            "AuditPolicyChange": 3,
        }
        failing = {**passing, "AuditPolicyChange": 1}
        self.assertEqual(collect_check("W-40", Api(passing)).status, "PASS")
        self.assertEqual(collect_check("W-40", Api(failing)).status, "FAIL")

    def test_kisa_w41_time_sync_pass_fail(self):
        class Api:
            def __init__(self, running, sync_type, server):
                self.inventory = {"service_running": running, "sync_type": sync_type, "ntp_server_configured": server}
            def time_sync_inventory(self):
                return self.inventory

        self.assertEqual(collect_check("W-41", Api(True, "NTP", True)).status, "PASS")
        self.assertEqual(collect_check("W-41", Api(True, "NT5DS", False)).status, "PASS")
        self.assertEqual(collect_check("W-41", Api(False, "NTP", True)).status, "FAIL")
        self.assertEqual(collect_check("W-41", Api(True, "NoSync", False)).status, "FAIL")

    def test_kisa_w42_event_log_size_and_retention_boundary(self):
        class Api:
            def __init__(self, sizes):
                self.sizes = sizes
            def event_log_inventory(self):
                return [{"name": name, "maximum_size_kb": size, "log_mode": "Circular"} for name, size in self.sizes]

        failing = collect_check("W-42", Api([("Security", 10239)]))
        self.assertEqual(failing.status, "FAIL")
        manual = collect_check("W-42", Api([("Security", 10240), ("System", 20480)]))
        self.assertEqual(manual.status, "UNABLE")
        self.assertTrue(manual.manual_review_required)

    def test_kisa_w43_log_directory_access_states(self):
        class Api:
            def __init__(self, directories):
                self.directories = directories
            def log_directory_inventory(self):
                return self.directories

        safe = [{"present": True, "everyone_access": False}, {"present": True, "everyone_access": False}]
        unsafe = [{"present": True, "everyone_access": True}, {"present": True, "everyone_access": False}]
        self.assertEqual(collect_check("W-43", Api(safe)).status, "PASS")
        self.assertEqual(collect_check("W-43", Api(unsafe)).status, "FAIL")
        self.assertEqual(collect_check("W-43", Api([])).status, "UNABLE")

    def test_kisa_w44_remote_registry_pass_fail(self):
        class Api:
            def __init__(self, running):
                self.running = running
            def remote_registry_running(self):
                return self.running

        self.assertEqual(collect_check("W-44", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-44", Api(True)).status, "FAIL")

    def test_kisa_w45_antivirus_installation_states(self):
        class Api:
            def __init__(self, available):
                self.available = available
            def antivirus_inventory(self):
                return {"defender_status_available": self.available, "antivirus_enabled": self.available, "signature_last_updated": None}

        self.assertEqual(collect_check("W-45", Api(True)).status, "PASS")
        manual = collect_check("W-45", Api(False))
        self.assertEqual(manual.status, "UNABLE")
        self.assertTrue(manual.manual_review_required)

    def test_kisa_w46_sam_acl_pass_fail(self):
        class Api:
            def __init__(self, unexpected):
                self.unexpected = unexpected
            def sam_acl_inventory(self):
                return {"access_rule_count": 2 + self.unexpected, "unexpected_principal_count": self.unexpected}

        self.assertEqual(collect_check("W-46", Api(0)).status, "PASS")
        self.assertEqual(collect_check("W-46", Api(1)).status, "FAIL")

    def test_kisa_w47_screen_saver_requires_user_review(self):
        class Api:
            def screen_saver_inventory(self):
                return {"enabled": True, "password_protected": True, "timeout_seconds": 600}

        result = collect_check("W-47", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertEqual(result.current_value["timeout_seconds"], 600)

    def test_kisa_w48_shutdown_without_logon_states(self):
        class Api:
            def __init__(self, enabled):
                self.enabled = enabled
            def shutdown_without_logon(self):
                return self.enabled

        self.assertEqual(collect_check("W-48", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-48", Api(True)).status, "FAIL")
        self.assertEqual(collect_check("W-48", Api(None)).status, "UNABLE")

    def test_kisa_w49_remote_shutdown_right_pass_fail(self):
        class Api:
            def __init__(self, count, unexpected):
                self.inventory = {"principal_count": count, "unexpected_principal_count": unexpected}
            def remote_shutdown_principal_counts(self):
                return self.inventory

        self.assertEqual(collect_check("W-49", Api(1, 0)).status, "PASS")
        self.assertEqual(collect_check("W-49", Api(2, 1)).status, "FAIL")
        self.assertEqual(collect_check("W-49", Api(0, 0)).status, "FAIL")

    def test_kisa_w50_crash_on_audit_fail_states(self):
        class Api:
            def __init__(self, enabled):
                self.enabled = enabled
            def crash_on_audit_fail(self):
                return self.enabled

        self.assertEqual(collect_check("W-50", Api(False)).status, "PASS")
        self.assertEqual(collect_check("W-50", Api(True)).status, "FAIL")
        self.assertEqual(collect_check("W-50", Api(None)).status, "UNABLE")

    def test_kisa_w51_anonymous_enumeration_states(self):
        class Api:
            def __init__(self, first, second):
                self.policy = {"restrict_anonymous": first, "restrict_anonymous_sam": second}
            def anonymous_enumeration_restricted(self):
                return self.policy

        self.assertEqual(collect_check("W-51", Api(1, 1)).status, "PASS")
        self.assertEqual(collect_check("W-51", Api(0, 1)).status, "FAIL")
        self.assertEqual(collect_check("W-51", Api(None, 1)).status, "UNABLE")

    def test_kisa_w52_auto_admin_logon_states(self):
        class Api:
            def __init__(self, value):
                self.value = value
            def auto_admin_logon(self):
                return self.value

        self.assertEqual(collect_check("W-52", Api(0)).status, "PASS")
        self.assertEqual(collect_check("W-52", Api(1)).status, "FAIL")
        self.assertEqual(collect_check("W-52", Api(2)).status, "UNABLE")

    def test_kisa_w53_removable_media_policy_states(self):
        class Api:
            def __init__(self, value):
                self.value = value
            def removable_media_eject_policy(self):
                return self.value

        self.assertEqual(collect_check("W-53", Api(0)).status, "PASS")
        self.assertEqual(collect_check("W-53", Api(1)).status, "FAIL")
        self.assertEqual(collect_check("W-53", Api(None)).status, "UNABLE")

    def test_kisa_w54_dos_registry_states(self):
        class Api:
            def __init__(self, values):
                self.values = values
            def dos_defense_registry(self):
                return self.values

        passing = {"SynAttackProtect": 1, "EnableDeadGWDetect": 0, "KeepAliveTime": 300000, "NoNameReleaseOnDemand": 1}
        missing = {**passing, "SynAttackProtect": None}
        different = {**passing, "KeepAliveTime": 600000}
        self.assertEqual(collect_check("W-54", Api(passing)).status, "PASS")
        self.assertEqual(collect_check("W-54", Api(missing)).status, "FAIL")
        self.assertEqual(collect_check("W-54", Api(different)).status, "UNABLE")

    def test_kisa_w55_printer_driver_policy_states(self):
        class Api:
            def __init__(self, prevented):
                self.prevented = prevented
            def printer_driver_installation_prevented(self):
                return self.prevented

        self.assertEqual(collect_check("W-55", Api(True)).status, "PASS")
        self.assertEqual(collect_check("W-55", Api(False)).status, "FAIL")
        self.assertEqual(collect_check("W-55", Api(None)).status, "UNABLE")

    def test_kisa_w56_smb_session_policy_states(self):
        class Api:
            def __init__(self, forced, timeout):
                self.policy = {"enable_forced_logoff": forced, "autodisconnect_minutes": timeout}
            def smb_session_policy(self):
                return self.policy

        self.assertEqual(collect_check("W-56", Api(1, 15)).status, "PASS")
        self.assertEqual(collect_check("W-56", Api(0, 15)).status, "FAIL")
        self.assertEqual(collect_check("W-56", Api(1, 16)).status, "FAIL")
        self.assertEqual(collect_check("W-56", Api(None, 15)).status, "UNABLE")

    def test_kisa_w57_logon_warning_pass_fail(self):
        class Api:
            def __init__(self, caption, text):
                self.warning = {"caption_configured": caption, "text_configured": text}
            def logon_warning_inventory(self):
                return self.warning

        self.assertEqual(collect_check("W-57", Api(True, True)).status, "PASS")
        self.assertEqual(collect_check("W-57", Api(False, True)).status, "FAIL")
        self.assertEqual(collect_check("W-57", Api(True, False)).status, "FAIL")

    def test_kisa_w58_home_directory_acl_pass_fail(self):
        class Api:
            def __init__(self, exposed):
                self.exposed = exposed
            def user_home_acl_inventory(self):
                return {"profile_count": 3, "everyone_access_count": self.exposed}

        self.assertEqual(collect_check("W-58", Api(0)).status, "PASS")
        self.assertEqual(collect_check("W-58", Api(1)).status, "FAIL")

    def test_kisa_w59_lan_manager_level_states(self):
        class Api:
            def __init__(self, level):
                self.level = level
            def lan_manager_authentication_level(self):
                return self.level

        self.assertEqual(collect_check("W-59", Api(3)).status, "PASS")
        self.assertEqual(collect_check("W-59", Api(5)).status, "PASS")
        self.assertEqual(collect_check("W-59", Api(2)).status, "FAIL")
        self.assertEqual(collect_check("W-59", Api(None)).status, "UNABLE")

    def test_kisa_w60_secure_channel_states(self):
        class Api:
            def __init__(self, joined, values):
                self.policy = {
                    "domain_joined": joined,
                    "require_sign_or_seal": values[0],
                    "seal_secure_channel": values[1],
                    "sign_secure_channel": values[2],
                }
            def secure_channel_policy(self):
                return self.policy

        self.assertEqual(collect_check("W-60", Api(False, (None, None, None))).status, "NA")
        self.assertEqual(collect_check("W-60", Api(True, (1, 1, 1))).status, "PASS")
        self.assertEqual(collect_check("W-60", Api(True, (1, 0, 1))).status, "FAIL")
        self.assertEqual(collect_check("W-60", Api(True, (1, None, 1))).status, "UNABLE")

    def test_kisa_w61_filesystem_states(self):
        class Api:
            def __init__(self, volume_count, ntfs, fat, other):
                self.inventory = {
                    "volume_count": volume_count,
                    "ntfs_count": ntfs,
                    "fat_count": fat,
                    "other_filesystem_count": other,
                }
            def fixed_volume_inventory(self):
                return self.inventory

        self.assertEqual(collect_check("W-61", Api(2, 2, 0, 0)).status, "PASS")
        self.assertEqual(collect_check("W-61", Api(2, 1, 1, 0)).status, "FAIL")
        self.assertEqual(collect_check("W-61", Api(2, 1, 0, 1)).status, "UNABLE")

    def test_kisa_w62_startup_requires_manual_review(self):
        class Api:
            def startup_inventory(self):
                return {
                    "startup_command_count": 3,
                    "automatic_service_count": 20,
                    "startup_identifiers": ["SensitiveStartup"],
                    "automatic_service_identifiers": ["SensitiveService"],
                }

        result = collect_check("W-62", Api())
        self.assertEqual(result.status, "UNABLE")
        self.assertTrue(result.manual_review_required)
        self.assertEqual(result.current_value["startup_command_count"], 3)
        self.assertNotIn("SensitiveStartup", result.current_value["startup_items_masked"])

    def test_kisa_w63_kerberos_clock_skew_states(self):
        class Api:
            def __init__(self, joined, skew):
                self.policy = {"domain_joined": joined, "maximum_clock_skew_minutes": skew}
            def kerberos_clock_skew_policy(self):
                return self.policy

        self.assertEqual(collect_check("W-63", Api(False, None)).status, "UNABLE")
        self.assertEqual(collect_check("W-63", Api(True, 5)).status, "PASS")
        self.assertEqual(collect_check("W-63", Api(True, 6)).status, "FAIL")
        self.assertEqual(collect_check("W-63", Api(True, None)).status, "UNABLE")

    def test_kisa_w64_firewall_profile_states(self):
        class Api:
            def __init__(self, profiles):
                self.profiles = profiles
            def firewall_profile_inventory(self):
                return self.profiles

        enabled = [{"name": "Domain", "enabled": True}, {"name": "Private", "enabled": True}]
        disabled = [{"name": "Domain", "enabled": True}, {"name": "Public", "enabled": False}]
        self.assertEqual(collect_check("W-64", Api(enabled)).status, "PASS")
        self.assertEqual(collect_check("W-64", Api(disabled)).status, "FAIL")
        self.assertEqual(collect_check("W-64", Api([])).status, "UNABLE")


if __name__ == "__main__":
    unittest.main()
