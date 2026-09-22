import tempfile
import unittest
from pathlib import Path

from agent.client import AgentClient, CommunicationError, MockApi
from agent.identity import AgentIdentity
from agent.inventory import collect_inventory
from agent.results import WindowsEvidence, build_mock_check_result
from agent.tasks import InvalidTask
from agent.windows_checks import WINDOWS_CHECKS, collect_check


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

    def test_invalid_claim_response_is_rejected(self):
        self.mock.tasks.append({"scan_scope": "FULL"})
        with self.assertRaises(InvalidTask):
            self.client.claim_check()

    def test_all_documented_windows_items_are_registered(self):
        self.assertEqual(len(WINDOWS_CHECKS), 64)
        self.assertEqual(set(WINDOWS_CHECKS), {f"W-{i:02d}" for i in range(1, 65)})

    def test_criteria_missing_returns_unable_without_inference(self):
        observation = collect_check("W-27")
        self.assertEqual(observation.status, "UNABLE")
        self.assertEqual(observation.reason_code, "CHECK_CRITERIA_NOT_DOCUMENTED")
        self.assertIn("version", observation.current_value)

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

    def test_kisa_w05_is_unable_without_security_policy_reader(self):
        result = collect_check("W-05")
        self.assertEqual(result.status, "UNABLE")
        self.assertEqual(result.reason_code, "LOCAL_SECURITY_POLICY_READ_NOT_IMPLEMENTED")


if __name__ == "__main__":
    unittest.main()
