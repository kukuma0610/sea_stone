import unittest
from dataclasses import replace
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agent.checks.common import CheckObservation
from agent.hardening import (
    ApprovalGate, HardeningMode, HardeningRejected, HardeningRunner,
    HardeningState, PlanningRejected, SEMI_AUTO_ALLOWLIST, create_plan,
    SnapshotStore,
)


class FakeAction:
    code = "W-07"
    path = r"SOFTWARE\OSGuardTest"
    name = "Policy"

    def __init__(self, *, fail=False, exists=True):
        self.value = 1 if exists else None
        self.exists = exists
        self.kind = 4 if exists else None
        self.applied = 0
        self.fail = fail

    def capture(self):
        return {"exists": self.exists, "value": self.value, "registry_type": self.kind}

    def apply(self):
        self.applied += 1
        if self.fail:
            raise OSError("mock write failed")
        self.exists = True
        self.value = 0
        self.kind = 4

    def restore(self, snapshot):
        self.exists = snapshot["existed"]
        self.value = snapshot["previous_value"]
        self.kind = snapshot["value_type"]


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.store = SnapshotStore(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def observation(self, code="W-07", status="FAIL"):
        return CheckObservation(code, status, "TEST", {"value": 1})

    def test_modes_have_no_auto_and_allowlist_is_fixed(self):
        self.assertEqual({mode.value for mode in HardeningMode}, {"SEMI_AUTO", "MANUAL"})
        self.assertEqual(
            SEMI_AUTO_ALLOWLIST,
            frozenset({"W-07", "W-13", "W-15", "W-48", "W-50", "W-52", "W-53", "W-59"}),
        )

    def test_planner_rejects_unable_pass_and_na(self):
        for status in ("UNABLE", "PASS", "NA"):
            with self.subTest(status=status), self.assertRaises(PlanningRejected):
                create_plan(self.observation(status=status))

    def test_planner_classifies_all_codes_and_manual_never_runs(self):
        semi = create_plan(self.observation("W-07"))
        manual = create_plan(self.observation("W-01"))
        self.assertEqual(semi.mode, HardeningMode.SEMI_AUTO)
        self.assertTrue(semi.approval_required)
        self.assertFalse(semi.approved)
        self.assertIn("양호:", semi.kisa_criteria)
        self.assertIn("취약:", semi.kisa_criteria)
        self.assertEqual(manual.mode, HardeningMode.MANUAL)
        self.assertTrue(manual.manual_required)
        self.assertTrue(manual.manual_guide)
        with self.assertRaises(HardeningRejected):
            HardeningRunner(ApprovalGate(), snapshot_store=self.store).run(manual, object())

        for number in range(1, 65):
            code = f"W-{number:02d}"
            plan = create_plan(self.observation(code))
            expected = HardeningMode.SEMI_AUTO if code in SEMI_AUTO_ALLOWLIST else HardeningMode.MANUAL
            self.assertEqual(plan.mode, expected)

    def test_unapproved_and_non_admin_execution_are_blocked_without_apply(self):
        plan = create_plan(self.observation())
        action = FakeAction()
        gate = ApprovalGate()
        runner = HardeningRunner(gate, administrator_check=lambda: True, snapshot_store=self.store)
        with patch("agent.hardening.runner.get_action", return_value=action):
            with self.assertRaises(HardeningRejected):
                runner.run(plan, object())
        waiting = gate.request(plan)
        approved, receipt = gate.approve(waiting, approved=True)
        runner = HardeningRunner(gate, administrator_check=lambda: False, snapshot_store=self.store)
        with patch("agent.hardening.runner.get_action", return_value=action):
            with self.assertRaises(HardeningRejected):
                runner.run(approved, receipt)
        self.assertEqual(action.applied, 0)

    def test_explicit_approval_runs_allowlisted_action_and_rechecks(self):
        gate = ApprovalGate()
        waiting = gate.request(create_plan(self.observation()))
        approved, receipt = gate.approve(waiting, approved=True)
        action = FakeAction()
        checks = iter((self.observation(status="FAIL"), self.observation(status="PASS")))
        runner = HardeningRunner(
            gate, checker=lambda code, api: next(checks),
            administrator_check=lambda: True, snapshot_store=self.store,
        )
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
        self.assertEqual(result.state, HardeningState.SUCCESS)
        self.assertEqual(result.before["setting"]["value"], 1)
        self.assertEqual(result.after["setting"]["value"], 0)
        self.assertEqual(self.store.load(result.snapshot_id).previous_value, 1)
        self.assertTrue(result.changed)
        self.assertTrue(result.pass_transition)
        self.assertEqual(action.applied, 1)
        with self.assertRaises(HardeningRejected):
            runner.run(approved, receipt)

    def test_declined_approval_and_action_failure(self):
        gate = ApprovalGate()
        waiting = gate.request(create_plan(self.observation()))
        with self.assertRaises(HardeningRejected):
            gate.approve(waiting, approved=False)

        approved, receipt = gate.approve(waiting, approved=True)
        action = FakeAction(fail=True)
        runner = HardeningRunner(
            gate, checker=lambda code, api: self.observation(status="FAIL"),
            administrator_check=lambda: True, snapshot_store=self.store,
        )
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
        self.assertEqual(result.state, HardeningState.FAILED)
        self.assertFalse(result.changed)
        self.assertIn("mock write failed", result.error_reason)
        self.assertTrue(result.rollback.success)
        self.assertEqual(action.value, 1)

    def test_forged_approved_plan_without_receipt_is_rejected(self):
        plan = replace(create_plan(self.observation()), approved=True, state=HardeningState.APPROVED)
        runner = HardeningRunner(
            ApprovalGate(), administrator_check=lambda: True, snapshot_store=self.store
        )
        with self.assertRaises(HardeningRejected):
            runner.run(plan, object())

    def _successful_hardening(self, action):
        gate = ApprovalGate()
        waiting = gate.request(create_plan(self.observation()))
        approved, receipt = gate.approve(waiting, approved=True)
        checks = iter((self.observation(status="FAIL"), self.observation(status="PASS")))
        runner = HardeningRunner(
            gate, checker=lambda code, api: next(checks),
            administrator_check=lambda: True, snapshot_store=self.store,
        )
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
        return runner, approved, result

    def test_existing_value_hardening_and_explicit_rollback_restores_original(self):
        action = FakeAction()
        runner, plan, result = self._successful_hardening(action)
        runner._checker = lambda code, api: self.observation(status="FAIL")
        with patch("agent.hardening.runner.get_action", return_value=action):
            rollback = runner.rollback(code="W-07", snapshot_id=result.snapshot_id, plan_id=plan.plan_id)
        self.assertTrue(rollback.success)
        self.assertTrue(self.store.has_successful_rollback(result.snapshot_id))
        self.assertEqual((action.exists, action.value, action.kind), (True, 1, 4))
        with self.assertRaises(HardeningRejected):
            runner.rollback(code="W-07", snapshot_id=result.snapshot_id, plan_id=plan.plan_id)

    def test_absent_value_rollback_removes_created_value(self):
        action = FakeAction(exists=False)
        runner, plan, result = self._successful_hardening(action)
        runner._checker = lambda code, api: self.observation(status="UNABLE")
        with patch("agent.hardening.runner.get_action", return_value=action):
            rollback = runner.rollback(code="W-07", snapshot_id=result.snapshot_id, plan_id=plan.plan_id)
        self.assertTrue(rollback.success)
        self.assertFalse(action.exists)
        self.assertIsNone(action.value)

    def test_wrong_snapshot_and_non_admin_rollback_are_rejected(self):
        action = FakeAction()
        runner, plan, result = self._successful_hardening(action)
        with self.assertRaises(HardeningRejected):
            runner.rollback(code="W-13", snapshot_id=result.snapshot_id, plan_id=plan.plan_id)
        with self.assertRaises(HardeningRejected):
            runner.rollback(code="W-07", snapshot_id=result.snapshot_id, plan_id="other-plan")
        blocked = HardeningRunner(
            ApprovalGate(), administrator_check=lambda: False, snapshot_store=self.store
        )
        with self.assertRaises(HardeningRejected):
            blocked.rollback(code="W-07", snapshot_id=result.snapshot_id, plan_id=plan.plan_id)
        self.assertEqual(action.value, 0)

    def test_failed_post_check_automatically_rolls_back(self):
        gate = ApprovalGate()
        waiting = gate.request(create_plan(self.observation()))
        approved, receipt = gate.approve(waiting, approved=True)
        action = FakeAction()
        runner = HardeningRunner(
            gate, checker=lambda code, api: self.observation(status="FAIL"),
            administrator_check=lambda: True, snapshot_store=self.store,
        )
        with patch("agent.hardening.runner.get_action", return_value=action):
            result = runner.run(approved, receipt)
        self.assertEqual(result.state, HardeningState.FAILED)
        self.assertTrue(result.rollback.success)
        self.assertEqual(action.value, 1)


if __name__ == "__main__":
    unittest.main()
