"""로컬 LAB 증적의 읽기 전용 집계. Mock/미봉인/다른 VM·커밋 결과는 성공으로 세지 않는다."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.central.storage import DPAPI
from agent.checks.common import WINDOWS_CHECKS
from scripts import lab_hardening_policy as policy

ORDER = ("W-07", "W-13", "W-15", "W-48", "W-50", "W-52", "W-53", "W-59", "W-05",
         "W-08", "W-09", "W-10", "W-04", "W-12", "W-49", "W-55", "W-36", "W-28")
STAGES = {"backup", "fail_preparation", "hardening", "recheck", "before_after_snapshot", "rollback", "original_restore"}


def read_json(path):
    policy.reject_reparse(path)
    policy.require(path.stat().st_size <= 1024*1024, "RESULT_TOO_LARGE")
    return json.loads(path.read_text(encoding="utf-8"))


def verified_report(path, root, vm, commit):
    data = read_json(path)
    if data.get("execution_kind") == "MOCK_UNIT_TEST":
        return None, "MOCK"
    policy.require(data.get("execution_kind") == "ISOLATED_VM_LAB", "RESULT_KIND_INVALID")
    if data.get("vm_uuid") != vm["uuid"] or data.get("commit") != commit:
        return None, "OTHER_SCOPE"
    report_id = str(UUID(data["report_id"]))
    policy.require(path.name == report_id+".result.json", "RESULT_ID_MISMATCH")
    sealed = path.with_suffix(".dpapi")
    policy.reject_reparse(sealed)
    policy.require(sealed.stat().st_size <= 65536, "RESULT_SEAL_INVALID")
    policy.require(DPAPI().unprotect(sealed.read_bytes()) == hashlib.sha256(path.read_bytes()).digest(), "RESULT_SEAL_INVALID")
    approval_id = str(UUID(data["approval_id"]))
    approval_path = root/(approval_id+".approval.json")
    approval = read_json(approval_path)
    encoded = hashlib.sha256(json.dumps(approval, sort_keys=True).encode()).hexdigest()
    policy.require(encoded == data["approval_sha256"], "APPROVAL_HASH_MISMATCH")
    used = root/(approval_id+".used")
    policy.reject_reparse(used)
    policy.require(used.read_text(encoding="utf-8") == encoded, "APPROVAL_USE_UNVERIFIED")
    policy.require(approval["code"] == data["code"] and approval["commit"] == commit
                   and approval["vm_uuid"] == vm["uuid"] and approval["max_uses"] == 1
                   and approval["snapshot"]["id"] == data["snapshot_id"], "APPROVAL_SCOPE_MISMATCH")
    started, finished = policy.utc(data["started_at"]), policy.utc(data["finished_at"])
    policy.require(policy.utc(approval["issued_at"]) <= started < policy.utc(approval["expires_at"])
                   and started <= finished, "RESULT_TIME_INVALID")
    artifacts = data["artifacts"]
    expected = {report_id+".console.log"}
    for field, subdir in (("original_snapshot_id", "originals"), ("hardening_snapshot_id", "hardening-snapshots")):
        if data.get(field):
            snapshot_id = str(UUID(data[field]))
            expected.add(subdir+"/"+snapshot_id+".json")
    policy.require(set(artifacts) == expected, "RESULT_ARTIFACTS_INVALID")
    for relative in expected:
        artifact = root/relative
        policy.reject_reparse(artifact)
        policy.require(hashlib.sha256(artifact.read_bytes()).hexdigest() == artifacts[relative], "RESULT_ARTIFACT_CHANGED")
        if relative.endswith(".json"):
            snapshot = read_json(artifact)
            field = "original_snapshot_id" if relative.startswith("originals/") else "hardening_snapshot_id"
            plan = "lab-"+approval_id if field == "original_snapshot_id" else data.get("plan_id")
            policy.require(snapshot.get("code") == data["code"] and snapshot.get("snapshot_id") == data[field]
                           and snapshot.get("plan_id") == plan, "RESULT_SNAPSHOT_SCOPE_MISMATCH")
            if field == "hardening_snapshot_id" and data.get("status") == "PASS":
                policy.require(any(r.get("success") is True and r.get("code") == data["code"]
                                   and r.get("plan_id") == plan and r.get("snapshot_id") == data[field]
                                   and r.get("check_result", {}).get("status") == "FAIL"
                                   for r in snapshot.get("rollback_results", [])), "ROLLBACK_RECORD_UNVERIFIED")
    return data, "VERIFIED"


def passed(data):
    return (data.get("status") == "PASS" and data.get("recovery_required") is False
            and data.get("hardening_state") == "SUCCESS"
            and all(data.get("stages", {}).get(stage) == "PASS" for stage in STAGES)
            and data.get("prepared_check_status") == "FAIL" and data.get("after_check_status") == "PASS"
            and data.get("rollback_check_status") == "FAIL"
            and data.get("original_check_status") in {"PASS", "FAIL", "NA", "UNABLE"}
            and data.get("restored_check_status") == data["original_check_status"]
            and bool(data.get("original_snapshot_id")) and bool(data.get("hardening_snapshot_id"))
            and (data["code"] not in {"W-28", "W-36"} or data.get("console_confirmed") is True))


def summarize(root, vm, commit):
    policy.reject_reparse(root)
    selected, excluded, rejected = {}, {"MOCK": 0, "OTHER_SCOPE": 0}, []
    for path in sorted(root.glob("*.result.json")):
        try:
            data, kind = verified_report(path, root, vm, commit)
            if data is None:
                excluded[kind] += 1
                continue
            policy.require(data["code"] in ORDER, "RESULT_CODE_INVALID")
            date = policy.utc(data["finished_at"])
            policy.require(data["code"] not in selected or date != selected[data["code"]][0], "AMBIGUOUS_RESULT_ORDER")
            if data["code"] not in selected or date > selected[data["code"]][0]:
                selected[data["code"]] = (date, data, str(path))
        except Exception as exc:
            rejected.append({"path": str(path), "reason": str(exc) if isinstance(exc, policy.LabRejected) else type(exc).__name__})
    rows = []
    for code in ORDER:
        row = {"code": code, "item_name": WINDOWS_CHECKS[code], "status": "NOT_RUN", "hardening": "-",
               "recheck": "-", "rollback": "-", "original_restore": "-", "reason": "NO_VERIFIED_VM_RESULT", "evidence": ""}
        if code in selected:
            _, data, evidence = selected[code]
            stages = data.get("stages", {})
            status = "PASS" if passed(data) else ("SKIP" if data.get("status") == "SKIP" else "FAIL")
            row.update(status=status, hardening=stages.get("hardening", "-"), recheck=stages.get("recheck", "-"),
                       rollback=stages.get("rollback", "-"), original_restore=stages.get("original_restore", "-"),
                       original_status=data.get("original_check_status", "-"), after_status=data.get("after_check_status", "-"),
                       restored_status=data.get("restored_check_status", "-"), evidence=evidence,
                       failure_stage=data.get("failure_stage", ""), runner_error_type=data.get("runner_error_type", ""),
                       runner_winerror=data.get("runner_winerror", ""),
                       console_log=str(Path(evidence).parent/(data["report_id"]+".console.log")),
                       reason=data.get("reason_code", "ALL_STAGES_VERIFIED" if status == "PASS" else "INCOMPLETE_E2E"))
        rows.append(row)
    blocked = bool(rejected) or (root/"ACTIVE_OR_RECOVERY_REQUIRED").exists() or any(r["status"] in {"FAIL", "SKIP"} for r in rows)
    return {"vm_uuid": vm["uuid"], "commit": commit, "actual_success": sum(r["status"] == "PASS" for r in rows),
            "total": 18, "rows": rows, "excluded": excluded, "rejected": rejected, "stop_required": blocked,
            "next_code": None if blocked else next((r["code"] for r in rows if r["status"] == "NOT_RUN"), None)}


def main(argv=None):
    argparse.ArgumentParser(description="봉인된 현재 VM/커밋의 LAB E2E 집계; 정책 변경·하드닝 없음").parse_args(argv)
    try:
        policy.require(policy.e2e._is_administrator(), "ADMINISTRATOR_REQUIRED")
        result = summarize(policy.lab_state_root(), policy.identity(), policy.source_commit())
        print("| 코드 | 하드닝 적용 | 재점검 PASS | Rollback | 최종 원복 | 최종 결과 |")
        print("|---|---|---|---|---|---|")
        for row in result["rows"]:
            print(f"| {row['code']} | {row['hardening']} | {row['recheck']} | {row['rollback']} | {row['original_restore']} | {row['status']} |")
            if row["status"] in {"FAIL", "SKIP"}:
                print(f"[{row['code']}] stage={row['failure_stage']} reason={row['reason']} type={row['runner_error_type']} winerror={row['runner_winerror']}")
        for rejected in result["rejected"]:
            print(f"[미검증 증적] {rejected['reason']}: {rejected['path']}")
        print(f"실환경 검증 성공: {result['actual_success']}/18; 다음 항목: {result['next_code']}; 중단 필요: {result['stop_required']}")
        directory = ROOT/"results/lab-e2e-summary"
        policy.reject_reparse(directory)
        directory.mkdir(parents=True, exist_ok=True)
        stem = str(uuid4())
        with (directory/(stem+".json")).open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
        fields = ["code", "item_name", "status", "hardening", "recheck", "rollback", "original_restore",
                  "original_status", "after_status", "restored_status", "failure_stage", "runner_error_type",
                  "runner_winerror", "reason", "evidence", "console_log"]
        with (directory/(stem+".csv")).open("x", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(result["rows"])
        print(f"집계 JSON/CSV: {directory/stem}")
        return 1 if result["stop_required"] else 0
    except Exception as exc:
        print(f"[집계 실패] {str(exc) if isinstance(exc, policy.LabRejected) else type(exc).__name__}; VM 성공 판정 없음")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
