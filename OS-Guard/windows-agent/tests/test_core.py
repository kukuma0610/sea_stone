import unittest
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agent.checks.common import CheckObservation
from agent.core import AgentCore, CoreRejected, CoreState
from agent.hardening import HardeningRunner, PlanningRejected, SnapshotStore
from tests.test_hardening import FakeAction


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.action = FakeAction()
        self.state = CoreState()
        self.calls = []

        def checker(code, api=None):
            self.calls.append(code)
            status = "PASS" if code == "W-07" and self.action.applied else "FAIL"
            return CheckObservation(code, status, "TEST", {"value": self.action.value})

        self.checker = checker

        def factory(gate, **kwargs):
            return HardeningRunner(
                gate, **kwargs, administrator_check=lambda: True,
                snapshot_store=SnapshotStore(self.temp.name),
            )

        self.factory = factory
        self.core = AgentCore(self.state, checker=checker, runner_factory=factory)

    def plan(self, code="W-07"):
        self.core.dispatch("CHECK_WINDOWS", job_id="job")
        return self.core.dispatch("CREATE_HARDENING_PLAN", job_id="job", code=code)["plan"]

    def test_all_checks_in_order_and_result_copy_isolation(self):
        report = self.core.dispatch("CHECK_WINDOWS", job_id="job")
        self.assertEqual(self.calls, [f"W-{i:02d}" for i in range(1, 65)])
        report["checks"][0]["status"] = "PASS"
        self.assertEqual(self.core.check_windows(job_id="job")["checks"][0]["status"], "FAIL")
        self.assertEqual(len(self.calls), 64)

    def test_request_sequence_shared_state_and_duplicate_execution(self):
        plan = self.plan()
        self.assertEqual(plan["state"], "WAITING_APPROVAL")
        second = AgentCore(self.state, checker=self.checker, runner_factory=self.factory)
        second.dispatch("APPROVE_HARDENING", job_id="job", plan_id=plan["plan_id"], approved=True)
        with patch("agent.hardening.runner.get_action", return_value=self.action):
            result = second.dispatch("RUN_HARDENING", job_id="job", plan_id=plan["plan_id"])
            duplicate = self.core.run_hardening(job_id="job", plan_id=plan["plan_id"])
        self.assertEqual(result, duplicate)
        self.assertEqual(self.action.applied, 1)
        self.assertEqual(result["result"]["after"]["check"]["status"], "PASS")
        self.assertTrue(result["result"]["snapshot_id"])

    def test_missing_approval_wrong_job_and_non_boolean_approval_rejected(self):
        plan_id = self.plan()["plan_id"]
        with self.assertRaises(CoreRejected):
            self.core.run_hardening(job_id="job", plan_id=plan_id)
        with self.assertRaises(CoreRejected):
            self.core.approve_hardening(job_id="other", plan_id=plan_id, approved=True)
        for value in (False, 1, "true", None):
            with self.assertRaises(CoreRejected):
                self.core.approve_hardening(job_id="job", plan_id=plan_id, approved=value)
        self.assertEqual(self.action.applied, 0)

    def test_manual_returns_only_plan_and_guide(self):
        plan = self.plan("W-01")
        result = self.core.run_hardening(job_id="job", plan_id=plan["plan_id"])
        self.assertTrue(result["plan"]["manual_required"])
        self.assertTrue(result["plan"]["manual_guide"])
        self.assertNotIn(plan["plan_id"], self.state.receipts)
        self.assertEqual(self.action.applied, 0)

    def test_collector_exception_isolated_and_unable_cannot_plan(self):
        def checker(code):
            if code == "W-07":
                raise OSError("secret must not leak")
            return CheckObservation(code, "PASS", "TEST", {})
        core = AgentCore(checker=checker)
        report = core.check_windows(job_id="job")
        self.assertEqual(len(report["checks"]), 64)
        self.assertEqual(report["checks"][6]["status"], "UNABLE")
        self.assertNotIn("secret", str(report))
        with self.assertRaises(PlanningRejected):
            core.create_hardening_plan(job_id="job", code="W-07")

    def test_commands_and_client_receipt_are_not_accepted(self):
        with self.assertRaises(CoreRejected):
            self.core.dispatch("COMMAND", job_id="job", command="whoami")
        with self.assertRaises(CoreRejected):
            self.core.dispatch("RUN_HARDENING", job_id="job", plan_id="x", receipt="fake")

    def test_concurrent_requests_execute_once(self):
        plan_id = self.plan()["plan_id"]
        self.core.approve_hardening(job_id="job", plan_id=plan_id, approved=True)
        with patch("agent.hardening.runner.get_action", return_value=self.action):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.core.run_hardening, job_id="job", plan_id=plan_id) for _ in range(2)]
                results = [future.result() for future in futures]
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.action.applied, 1)


if __name__ == "__main__":
    unittest.main()
