from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from scripts import lab_e2e_report as summary
from scripts import lab_hardening_e2e as lab
from scripts import lab_hardening_policy as policy

VM = {"uuid": "11111111-1111-1111-1111-111111111111", "sid": "S-1-5-21-1-1001"}
COMMIT = "a"*40


class MockDPAPI:
    def protect(self, value): return b"mock-seal:"+value
    def unprotect(self, value):
        if not value.startswith(b"mock-seal:"): raise ValueError("invalid test seal")
        return value[len(b"mock-seal:"):]


def fixture(root, code="W-07", mutate=None):
    # 인증/네이티브 실행 경계의 테스트 자료이며 실제 Windows 하드닝 증적이 아니다.
    report_id, approval_id, original_id, hardening_id, plan = [str(uuid4()) for _ in range(5)]
    now = datetime.now(timezone.utc)
    approval = {"code": code, "commit": COMMIT, "vm_uuid": VM["uuid"], "max_uses": 1,
                "issued_at": (now-timedelta(minutes=1)).isoformat(), "expires_at": (now+timedelta(minutes=1)).isoformat(),
                "snapshot": {"id": "mock-snapshot"}}
    digest = hashlib.sha256(json.dumps(approval, sort_keys=True).encode()).hexdigest()
    (root/(approval_id+".approval.json")).write_text(json.dumps(approval))
    (root/(approval_id+".used")).write_text(digest)
    artifacts = {}
    for subdir, sid, plan_id in (("originals", original_id, "lab-"+approval_id), ("hardening-snapshots", hardening_id, plan)):
        (root/subdir).mkdir(exist_ok=True)
        path = root/subdir/(sid+".json")
        snap = {"snapshot_id": sid, "code": code, "plan_id": plan_id}
        if subdir == "hardening-snapshots":
            snap["rollback_results"] = [{"success": True, "code": code, "plan_id": plan,
                                         "snapshot_id": hardening_id, "check_result": {"status": "FAIL"}}]
        path.write_text(json.dumps(snap))
        artifacts[subdir+"/"+path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    log = root/(report_id+".console.log")
    log.write_text("Mock stage output")
    artifacts[log.name] = hashlib.sha256(log.read_bytes()).hexdigest()
    data = {"report_id": report_id, "approval_id": approval_id, "approval_sha256": digest,
            "code": code, "commit": COMMIT, "vm_uuid": VM["uuid"], "snapshot_id": "mock-snapshot",
            "execution_kind": "ISOLATED_VM_LAB", "status": "PASS", "recovery_required": False,
            "started_at": now.isoformat(), "finished_at": now.isoformat(), "hardening_state": "SUCCESS",
            "stages": {stage: "PASS" for stage in summary.STAGES}, "original_check_status": "UNABLE",
            "restored_check_status": "UNABLE", "prepared_check_status": "FAIL", "after_check_status": "PASS",
            "rollback_check_status": "FAIL", "original_snapshot_id": original_id,
            "hardening_snapshot_id": hardening_id, "plan_id": plan, "artifacts": artifacts}
    if mutate: mutate(data)
    path = root/(report_id+".result.json")
    path.write_text(json.dumps(data), encoding="utf-8")
    path.with_suffix(".dpapi").write_bytes(MockDPAPI().protect(hashlib.sha256(path.read_bytes()).digest()))
    return path, data


class ReportTests(unittest.TestCase):
    def test_no_results_never_claims_real_success(self):
        with TemporaryDirectory() as temp:
            report = summary.summarize(Path(temp), VM, COMMIT)
            self.assertEqual(report["actual_success"], 0)
            self.assertEqual(len(report["rows"]), 18)
            self.assertTrue(all(row["status"] == "NOT_RUN" for row in report["rows"]))
            self.assertEqual(report["next_code"], "W-07")

    def test_mock_and_other_scope_results_never_count(self):
        with TemporaryDirectory() as temp, patch.object(summary, "DPAPI", MockDPAPI):
            root = Path(temp)
            fixture(root, mutate=lambda d: d.update(execution_kind="MOCK_UNIT_TEST"))
            fixture(root, mutate=lambda d: d.update(commit="b"*40))
            report = summary.summarize(root, VM, COMMIT)
            self.assertEqual(report["actual_success"], 0)
            self.assertEqual(report["excluded"], {"MOCK": 1, "OTHER_SCOPE": 1})

    def test_mock_authenticated_boundary_counts_only_complete_e2e(self):
        with TemporaryDirectory() as temp, patch.object(summary, "DPAPI", MockDPAPI):
            root = Path(temp)
            fixture(root)
            result = summary.summarize(root, VM, COMMIT)
            self.assertEqual(result["actual_success"], 1)
            self.assertEqual(result["next_code"], "W-13")
            self.assertEqual(result["rows"][0]["original_status"], "UNABLE")

    def test_unsigned_or_tampered_evidence_is_not_counted(self):
        for kind in ("seal", "report", "log", "snapshot"):
            with self.subTest(kind=kind), TemporaryDirectory() as temp, patch.object(summary, "DPAPI", MockDPAPI):
                root = Path(temp)
                path, data = fixture(root)
                if kind == "seal": path.with_suffix(".dpapi").unlink()
                elif kind == "report": path.write_text(path.read_text()+" ")
                elif kind == "log": (root/(data["report_id"]+".console.log")).write_text("tampered")
                else: (root/"originals"/(data["original_snapshot_id"]+".json")).write_text("{}")
                result = summary.summarize(root, VM, COMMIT)
                self.assertEqual(result["actual_success"], 0)
                self.assertTrue(result["stop_required"])

    def test_missing_phases_bad_recheck_restore_and_console_are_not_pass(self):
        mutations = [lambda d: d["stages"].pop("rollback"), lambda d: d.update(after_check_status="UNABLE"),
                     lambda d: d.update(restored_check_status="PASS"), lambda d: d.update(recovery_required=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate), TemporaryDirectory() as temp, patch.object(summary, "DPAPI", MockDPAPI):
                fixture(Path(temp), mutate=mutate)
                result = summary.summarize(Path(temp), VM, COMMIT)
                self.assertEqual(result["actual_success"], 0)
                self.assertIsNone(result["next_code"])
        with TemporaryDirectory() as temp, patch.object(summary, "DPAPI", MockDPAPI):
            fixture(Path(temp), code="W-28")
            self.assertEqual(summary.summarize(Path(temp), VM, COMMIT)["actual_success"], 0)

    def test_failure_skip_or_recovery_lock_stops_next_item(self):
        for status in ("FAIL", "SKIP"):
            with self.subTest(status=status), TemporaryDirectory() as temp, patch.object(summary, "DPAPI", MockDPAPI):
                fixture(Path(temp), mutate=lambda d: d.update(status=status))
                result = summary.summarize(Path(temp), VM, COMMIT)
                self.assertIsNone(result["next_code"])
                self.assertEqual(result["actual_success"], 0)
        with TemporaryDirectory() as temp:
            (Path(temp)/"ACTIVE_OR_RECOVERY_REQUIRED").write_text("mock lock")
            self.assertTrue(summary.summarize(Path(temp), VM, COMMIT)["stop_required"])

    def test_remote_items_require_console_before_real_execution(self):
        with patch.object(policy, "Lease") as lease:
            for code in ("W-28", "W-36"):
                with self.subTest(code=code), self.assertRaises(policy.LabRejected):
                    lab.run({"code": code}, "digest", lambda: None)
            lease.assert_not_called()
