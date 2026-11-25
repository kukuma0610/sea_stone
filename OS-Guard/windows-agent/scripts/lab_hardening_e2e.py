"""LAB-E2E-1 격리 VM 단일 시험. 운영 진입점과 별개이며 기본은 승인·환경 검증만 수행한다."""

import argparse
from contextlib import redirect_stdout
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab_hardening_policy as policy
from scripts import test_hardening_e2e as e2e
from scripts.run_hardening_validation import ConsoleLog
from agent.central.storage import DPAPI
from agent.checks.common import WINDOWS_CHECKS
import hashlib
import re


def check(condition, reason):
    policy.require(condition, reason)


def load_record(path):
    policy.reject_reparse(path)
    check(path.stat().st_size <= 32768, "APPROVAL_FILE_TOO_LARGE")
    def unique(pairs):
        data = {}
        for key, value in pairs:
            check(key not in data, "DUPLICATE_APPROVAL_FIELD")
            data[key] = value
        return data
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError):
        raise policy.ApprovalFieldsRejected([("approval_file", "JSON_INVALID")]) from None


def run(approval, digest, revalidate, *, evidence_kind="ISOLATED_VM_LAB", console_confirmed=False):
    check(evidence_kind in {"ISOLATED_VM_LAB", "MOCK_UNIT_TEST"}, "EVIDENCE_KIND_INVALID")
    code = approval["code"]
    check(evidence_kind != "ISOLATED_VM_LAB" or code not in {"W-28", "W-36"} or console_confirmed,
          "VMWARE_CONSOLE_NOT_CONFIRMED")
    lease = policy.Lease(approval, digest)
    lease.acquire()  # 다른 항목 실행 중·승인 재사용·복구 미확인 상태이면 변경 전에 거부한다.
    report = {"policy": "LAB-E2E-1", "risk": policy.RISK, "approval_id": approval["approval_id"],
              "approval_sha256": digest, "vm_uuid": approval["vm_uuid"], "commit": approval["commit"],
              "code": code, "snapshot_id": approval["snapshot"]["id"], "test_policy_used": True,
              "central_approved": False, "execution_kind": evidence_kind,
              "item_name": WINDOWS_CHECKS[code], "console_confirmed": console_confirmed,
              "started_at": datetime.now(timezone.utc).isoformat(), "status": "SKIP", "stages": {}}
    run_id = str(uuid4())
    report["report_id"] = run_id
    log_path = lease.folder / (run_id+".console.log")
    log = log_path.open("x", encoding="utf-8")
    output = redirect_stdout(ConsoleLog(sys.stdout, log))
    output.__enter__()
    changed = False
    restored = False
    rollback_failed = False
    original = original_snapshot = action = None
    stage = "ENVIRONMENT"
    try:
        revalidate()
        stage = "ORIGINAL_CAPTURE"
        action = e2e.get_action(code)
        original_check = e2e.collect_check(code)
        report["original_check_status"] = original_check.status
        print(f"[LAB] {code} {WINDOWS_CHECKS[code]} / 원본 CHECK={original_check.status}")
        if code == "W-28" and original_check.current_value.get("service_running") is False:
            raise policy.LabRejected("RDP_NOT_RUNNING")
        original = action.capture()
        stage = "ORIGINAL_BACKUP"
        policy.reject_reparse(lease.folder / "originals")
        originals = e2e.SnapshotStore(lease.folder / "originals")
        save = originals.create_transaction if isinstance(action, e2e.PolicyTransactionAction) else originals.create
        saved = save(code=code, plan_id="lab-" + approval["approval_id"], path=action.path,
                     value_name=action.name, captured=original)
        original_snapshot = originals.load(saved.snapshot_id)
        check(e2e.expected_setting(original_snapshot) == original, "ORIGINAL_BACKUP_MISMATCH")
        report["original_snapshot_id"] = saved.snapshot_id
        report["stages"]["backup"] = "PASS"
        print("[LAB] 원본 백업 재로드 검증 PASS")
        check(input(f"FAIL 준비 승인: PREPARE {code} 입력: ").strip() == f"PREPARE {code}", "PREPARATION_NOT_APPROVED")
        revalidate()
        check(action.capture() == original, "SETTING_CHANGED_BEFORE_PREPARE")
        stage = "FAIL_PREPARATION"
        changed = True  # 부분 변경 예외도 반드시 원본 복구 대상으로 취급한다.
        report["status"] = "FAIL"
        e2e.prepare_fail(action, original)
        observed = e2e.collect_check(code)
        report["prepared_check_status"] = observed.status
        check(observed.status == "FAIL", "PREPARED_CHECK_NOT_FAIL")
        prepared = action.capture()
        report["stages"]["fail_preparation"] = "PASS"
        print("[LAB] FAIL 준비 및 동일 CHECK FAIL 확인")
        stage = "PLAN_AND_APPROVAL"
        plan = e2e.create_plan(observed)
        report["plan_id"] = plan.plan_id
        gate = e2e.ApprovalGate()
        waiting = gate.request(plan)
        check(input(f"하드닝 승인: APPROVE {code} 입력: ").strip() == f"APPROVE {code}", "HARDENING_NOT_APPROVED")
        revalidate()
        approved, receipt = gate.approve(waiting, approved=True)
        policy.reject_reparse(lease.folder / "hardening-snapshots")
        store = e2e.SnapshotStore(lease.folder / "hardening-snapshots")
        runner = e2e.HardeningRunner(gate, snapshot_store=store)
        stage = "HARDENING"
        result = runner.run(approved, receipt)
        report["hardening_state"] = result.state.value
        report["stages"]["hardening"] = "PASS" if result.state is e2e.HardeningState.SUCCESS else "FAIL"
        if result.snapshot_id:
            report["hardening_snapshot_id"] = result.snapshot_id
        if result.error_reason:
            error_type = result.error_reason.split(":", 1)[0]
            report["runner_error_type"] = error_type if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", error_type) else "UNCLASSIFIED"
            winerror = re.search(r"\[WinError (\d+)\]", result.error_reason)
            if winerror: report["runner_winerror"] = int(winerror.group(1))
        rollback_failed = result.rollback is not None and not result.rollback.success
        check(result.state is e2e.HardeningState.SUCCESS, "HARDENING_FAILED")
        stage = "RECHECK_AFTER"
        report["after_check_status"] = e2e.collect_check(code).status
        report["stages"]["recheck"] = "PASS" if report["after_check_status"] == "PASS" else "FAIL"
        check(report["after_check_status"] == "PASS", "RECHECK_NOT_PASS")
        snapshot = store.load(result.snapshot_id)
        check(snapshot.code == code and snapshot.plan_id == plan.plan_id
              and e2e.expected_setting(snapshot) == prepared
              and result.before["setting"] == prepared
              and result.after["setting"] == action.capture()
              and result.before["check"]["status"] == "FAIL"
              and result.after["check"]["status"] == "PASS"
              and result.changed and result.pass_transition, "HARDENING_EVIDENCE_MISMATCH")
        report.update(plan_id=plan.plan_id, hardening_snapshot_id=result.snapshot_id)
        report["stages"].update(hardening="PASS", recheck="PASS", before_after_snapshot="PASS")
        print("[LAB] Hardening/재CHECK PASS 및 Before/After/Snapshot 일치")
        stage = "ROLLBACK"
        rollback = runner.rollback(code=code, snapshot_id=result.snapshot_id, plan_id=plan.plan_id)
        rollback_failed = not rollback.success or rollback.restored_setting != prepared
        check(rollback.success and rollback.restored_setting == prepared, "ROLLBACK_FAILED")
        report["rollback_check_status"] = e2e.collect_check(code).status
        rollback_failed = report["rollback_check_status"] != "FAIL"
        check(not rollback_failed, "ROLLBACK_CHECK_NOT_FAIL")
        report["stages"]["rollback"] = "PASS"
        report["status"] = "PASS"
        print("[LAB] Rollback 및 준비했던 FAIL 상태 확인 PASS")
    except (Exception, KeyboardInterrupt) as exc:
        # 원문 예외/레지스트리 값/계정명은 증적이나 콘솔에 복사하지 않는다.
        report["status"] = "FAIL" if changed else "SKIP"
        report["reason_code"] = str(exc) if isinstance(exc, policy.LabRejected) else type(exc).__name__
        report["failure_stage"] = stage
        print(f"[LAB 중단] {report['reason_code']}")
    finally:
        if changed and original_snapshot is not None:
            try:
                check(e2e._is_administrator(), "RESTORE_ADMINISTRATOR_REQUIRED")
                saved = originals.load(original_snapshot.snapshot_id)
                check(saved.code == code and saved.registry_path == action.path and saved.value_name == action.name
                      and e2e.expected_setting(saved) == original, "ORIGINAL_IDENTITY_MISMATCH")
                action.restore(asdict(saved))
                check(action.capture() == original, "ORIGINAL_SETTINGS_NOT_RESTORED")
                report["restored_check_status"] = e2e.collect_check(code).status
                check(report["restored_check_status"] == original_check.status, "ORIGINAL_CHECK_NOT_RESTORED")
                restored = True
                report["stages"]["original_restore"] = "PASS"
                print("[LAB] 최종 원본 값·타입·존재 여부 및 CHECK 상태 복구 PASS")
            except (Exception, KeyboardInterrupt):
                report.update(status="FAIL", reason_code="ORIGINAL_RESTORE_FAILED")
                report["failure_stage"] = "ORIGINAL_RESTORE"
                report["stages"]["original_restore"] = "FAIL"
                print("[LAB 복구 실패] 전체 시험 중단. 잠금·백업 보존, 하이퍼바이저 복구 필요")
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["recovery_required"] = (changed and not restored) or rollback_failed
        output.__exit__(None, None, None)
        log.close()
        report["artifacts"] = {log_path.name: hashlib.sha256(log_path.read_bytes()).hexdigest()}
        for field, subdirectory in (("original_snapshot_id", "originals"), ("hardening_snapshot_id", "hardening-snapshots")):
            if report.get(field):
                artifact = lease.folder / subdirectory / (report[field]+".json")
                policy.reject_reparse(artifact)
                report["artifacts"][subdirectory+"/"+artifact.name] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        path = lease.folder / (run_id + ".result.json")
        with path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        if evidence_kind == "ISOLATED_VM_LAB":
            # 로컬 관리자 CurrentUser 봉인이다. Central 서명/외부 인증이라고 주장하지 않는다.
            sealed = DPAPI().protect(hashlib.sha256(path.read_bytes()).digest())
            with path.with_suffix(".dpapi").open("xb") as stream:
                stream.write(sealed)
                stream.flush()
                os.fsync(stream.fileno())
        if not report["recovery_required"]:
            lease.release()
        print(f"[LAB 결과] {report['status']}; {path}")
    return 0 if report["status"] == "PASS" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="격리 VM 위험 수용 시험; 운영 안전 정책은 변경하지 않음")
    parser.add_argument("--code", required=True, choices=sorted(e2e.SEMI_AUTO_ALLOWLIST))
    parser.add_argument("--approval-file", required=True, type=Path)
    parser.add_argument("--execute", action="store_true", help="승인 검증·직접 입력·1회 소비 후에만 시험")
    parser.add_argument("--owner-certificate", type=Path, help="별도 신뢰 경로로 받은 책임자 공개 DER 인증서")
    parser.add_argument("--owner-cert-sha256", help="책임자 신원과 별도 확인된 인증서 DER SHA256")
    parser.add_argument("--export-approval-payload", type=Path, help="서명 요청용 정규화 원문만 새 파일로 내보내기; 승인/서명 생성 아님")
    args = parser.parse_args(argv)
    entered = False
    try:
        check(e2e._is_administrator(), "ADMINISTRATOR_REQUIRED")
        try:
            approval = load_record(args.approval_file)
        except OSError:
            raise policy.ApprovalFieldsRejected([("approval_file", "FILE_UNREADABLE_OR_MISSING")]) from None
        if args.export_approval_payload is not None:
            check(not args.execute, "EXPORT_CANNOT_EXECUTE")
            from scripts.lab_owner_signature import payload
            policy.reject_reparse(args.export_approval_payload)
            with args.export_approval_payload.open("xb") as stream:
                stream.write(payload(approval))
            print("[LAB 서명 요청 원문] 미서명 자료만 내보냄; 승인·환경 PASS·실행 허용 아님")
            return 0
        issues = policy.approval_field_issues(approval)
        if issues:
            raise policy.ApprovalFieldsRejected(issues)
        proof = ({"approval_file": args.approval_file.absolute(),
                  "certificate_file": args.owner_certificate.absolute(),
                  "certificate_sha256": args.owner_cert_sha256}
                 if args.owner_certificate is not None and args.owner_cert_sha256 else None)
        def revalidate():
            arguments = {"code": args.code, "vm": policy.identity(), "commit": policy.source_commit()}
            if proof is not None:
                arguments["external_proof"] = proof
            digest = policy.validate_approval(approval, **arguments)
            policy.environment()
            return digest
        digest = revalidate()
        print("[LAB 경고] PolicyOverdue 의미 미확정. 로컬 위험 수용 시험이며 Central 승인이 아닙니다.")
        if any(a.get("method") == "DETACHED_CMS_SHA256" for a in approval["approvers"]):
            print("[LAB 외부 승인] 고정 지문 기반 CMS 검증 완료; 인증서 폐기 상태는 자동 확인하지 않음")
        else:
            print("[LAB SID 승인] 현장 승인 기록 방식; 전자서명 검증 아님")
        print("[LAB 경고] VMware 격리·스냅샷 실재는 현장 관리자가 외부에서 확인해야 합니다.")
        print(f"[LAB 범위] VM={approval['vm_uuid']} commit={approval['commit']} "
              f"code={args.code} snapshot={approval['snapshot']['id']}")
        if not args.execute:
            print("[LAB 검증] 승인 형식·범위·독립 환경 조건 확인; 미소비, 설정 변경 없음")
            return 0
        phrase = f"RISK_ACCEPT {approval['approval_id']} {args.code}"
        check(input(f"VMware 스냅샷 확인: SNAPSHOT {approval['snapshot']['id']} 입력: ").strip()
              == f"SNAPSHOT {approval['snapshot']['id']}", "SNAPSHOT_NOT_CONFIRMED")
        check(input(f"관리자·시험 책임자 승인 문서 확인 후 {phrase} 입력: ").strip() == phrase, "RISK_NOT_CONFIRMED")
        console_confirmed = False
        if args.code in {"W-28", "W-36"}:
            check(input(f"VMware 콘솔 실제 접속 확인: CONSOLE {args.code} 입력: ").strip()
                  == f"CONSOLE {args.code}", "VMWARE_CONSOLE_NOT_CONFIRMED")
            console_confirmed = True
        entered = True
        return run(approval, digest, revalidate, console_confirmed=console_confirmed)
    except (Exception, KeyboardInterrupt) as exc:
        if isinstance(exc, policy.ApprovalFieldsRejected):
            for field, reason in exc.issues:
                print(f"[LAB 승인 필드] field={field} reason={reason}")
        reason = str(exc) if isinstance(exc, policy.LabRejected) else type(exc).__name__
        if entered:
            print(f"[LAB 실행 오류] {reason}; 추가 시험 금지, 잠금·백업·원복 상태 확인 필요")
        else:
            print(f"[LAB 거부] {reason}; 하드닝 실행 허용 안 함")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
