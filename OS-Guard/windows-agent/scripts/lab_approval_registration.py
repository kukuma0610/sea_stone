"""실제 Windows 로그인·직접 동의로 신규 LAB 승인과 감사 기록만 등록한다."""

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.central.storage import DPAPI
from agent.windows_service.security import sid_for_account, token_user
from scripts import lab_hardening_policy as policy
from scripts.lab_approval_pipe import ApprovalPipe

PREFIX = "windows-logon-v1:"


def now():
    return datetime.now(timezone.utc)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def folder():
    return policy.lab_state_root() / "registrations"


def write_new(path, raw):
    policy.reject_reparse(path)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def owner_logon(account, request):
    if account.startswith(".\\"):
        account = socket.gethostname()+account[1:]
    owner_sid = sid_for_account(account)
    policy.require(owner_sid != request["admin_sid"], "DISTINCT_APPROVERS_REQUIRED")
    request = {**request, "owner_sid": owner_sid, "nonce": secrets.token_hex(32), "protocol": "LAB-APPROVAL-1"}
    name = "OSGuardLabApproval-"+uuid4().hex
    pipe = ApprovalPipe(name, owner_sid)
    process = None
    try:
        executable = Path(policy.e2e.system_executable("gpresult.exe")).parent / "WindowsPowerShell/v1.0/powershell.exe"
        # 자격 증명은 Get-Credential/Windows 로그온에만 전달된다. Python이 암호를 받지 않는다.
        process = subprocess.Popen([str(executable), "-NoLogo", "-NoProfile", "-File",
                                    str(ROOT/"scripts/lab_owner_confirm.ps1"), "-PipeName", name, "-UserName", account],
                                   shell=False, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
        pipe.cancelled = lambda: process.poll() is not None
        actual_sid = pipe.approve(request)
        policy.require(actual_sid == owner_sid and actual_sid != request["admin_sid"], "OWNER_LOGON_SID_MISMATCH")
        policy.require(process.wait(timeout=30) == 0, "OWNER_CONFIRMATION_NOT_COMPLETED")
        return actual_sid
    finally:
        pipe.close()
        if process is not None and process.poll() is None:
            # 이 요청에서 생성한 로그인 보조 프로세스만 종료한다.
            process.terminate()
            process.wait(timeout=5)


def register(code, snapshot_id, *, evidence_kind="NATIVE_WINDOWS_LOGON"):
    policy.require(policy.e2e._is_administrator(), "ELEVATED_ADMINISTRATOR_REQUIRED")
    vm, commit = policy.identity(), policy.source_commit()
    policy.require(token_user() == vm["sid"], "ADMINISTRATOR_TOKEN_MISMATCH")
    policy.require(code in policy.e2e.SEMI_AUTO_ALLOWLIST, "CODE_NOT_ALLOWLISTED")
    policy.require(isinstance(snapshot_id, str) and snapshot_id.isprintable() and 0 < len(snapshot_id) <= 200,
                   "SNAPSHOT_ID_INVALID")
    # 실행 파일이 커밋에 포함되지 않았거나 변경됐으면 source_commit/추가 추적 검사가 거부한다.
    subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "--error-unmatch",
                             "scripts/lab_approval_registration.py", "scripts/lab_approval_pipe.py",
                             "scripts/lab_owner_confirm.ps1", "scripts/Register-LabApproval.ps1"], stderr=subprocess.DEVNULL)
    policy.require(not (policy.lab_state_root()/"ACTIVE_OR_RECOVERY_REQUIRED").exists(), "RECOVERY_REQUIRED")
    policy.environment()
    root = policy.lab_state_root()
    policy.reject_reparse(root)
    root.mkdir(parents=True, exist_ok=True)
    policy.restrict_acl(root)
    directory = folder()
    policy.reject_reparse(directory)
    directory.mkdir(exist_ok=True)
    policy.restrict_acl(directory)
    approval_id = str(uuid4())
    issued = now()
    audit_path = directory / (approval_id+".audit.jsonl")
    audit = audit_path.open("x", encoding="utf-8")
    def event(kind, **details):
        audit.write(json.dumps({"event": kind, "time": now().isoformat(), "kind": evidence_kind,
                                "approval_id": approval_id, **details}, ensure_ascii=True)+"\n")
        audit.flush()
        os.fsync(audit.fileno())
    event("REQUEST_CREATED", vm_uuid=vm["uuid"], commit=commit, code=code, snapshot_id=snapshot_id)
    try:
        print("[LAB] 승인 등록만 수행합니다. 실제 하드닝은 실행하지 않습니다.")
        print(f"[LAB 범위] VM={vm['uuid']} commit={commit} code={code} snapshot={snapshot_id}")
        print("[LAB 위험] PolicyOverdue=0 의미 미확정. 격리·업무 데이터/운영 Credential 없음 및 복구 수단을 확인하십시오.")
        policy.require(input(f"VMware 스냅샷 확인: SNAPSHOT {snapshot_id} 입력: ").strip() == f"SNAPSHOT {snapshot_id}", "SNAPSHOT_NOT_CONFIRMED")
        policy.require(input(f"현재 관리자 직접 위험 수용: ACCEPT {code} 입력: ").strip() == f"ACCEPT {code}", "ADMINISTRATOR_RISK_DECLINED")
        admin_time = now().isoformat()
        event("ADMINISTRATOR_ACCEPTED", sid=vm["sid"], approved_at=admin_time)
        account = input("TEST_OWNER의 실제 Windows 계정 이름(암호는 새 로그인 창에만 입력): ").strip()
        policy.require(0 < len(account) <= 256 and account.isprintable(), "OWNER_ACCOUNT_REQUIRED")
        request = {"approval_id": approval_id, "vm_uuid": vm["uuid"], "commit": commit,
                   "code": code, "snapshot_id": snapshot_id, "risk": policy.RISK, "admin_sid": vm["sid"]}
        owner_sid = owner_logon(account, request)
        policy.require(owner_sid != vm["sid"], "DISTINCT_APPROVERS_REQUIRED")
        owner_time = now().isoformat()
        event("TEST_OWNER_ACCEPTED", sid=owner_sid, approved_at=owner_time, authentication="WINDOWS_PIPE_TOKEN")
        # 책임자 로그온 이후 생긴 정책 세션·환경 변화도 다시 확인한다.
        policy.environment()
        policy.require(policy.identity() == vm and policy.source_commit() == commit, "APPROVAL_SCOPE_CHANGED")
        policy.require(now() < issued+timedelta(hours=1), "REGISTRATION_EXPIRED")
        policy.require(issued <= policy.utc(admin_time) <= policy.utc(owner_time) <= now(), "REGISTRATION_CLOCK_CHANGED")
        data = {"policy_version": "LAB-E2E-1", "approval_id": approval_id, "vm_uuid": vm["uuid"],
                "commit": commit, "code": code, "max_uses": 1, "issued_at": issued.isoformat(),
                "expires_at": (issued+timedelta(hours=1)).isoformat(), "isolated_vm": True,
                "no_operating_data_or_credentials": True, "risk": policy.RISK,
                "snapshot": {"id": snapshot_id, "confirmed": True, "recovery_procedure":
                    "Stop tests; use VMware console to restore the confirmed snapshot; verify original CHECK; obtain new approval and update the external use register."},
                "approvers": [
                    {"role": "ADMINISTRATOR", "sid": vm["sid"], "accepted": True, "approved_at": admin_time,
                     "reference": PREFIX+approval_id+":ADMINISTRATOR"},
                    {"role": "TEST_OWNER", "sid": owner_sid, "accepted": True, "approved_at": owner_time,
                     "reference": PREFIX+approval_id+":TEST_OWNER"}]}
        event("APPROVAL_COMPLETED", approval_sha256=digest(data))
    except BaseException as exc:
        event("REGISTRATION_ABORTED", reason=str(exc) if isinstance(exc, policy.LabRejected) else type(exc).__name__)
        raise
    finally:
        audit.close()
    seal = {"approval_id": approval_id, "approval_sha256": digest(data),
            "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(), "kind": evidence_kind}
    write_new(directory/(approval_id+".audit.dpapi"), DPAPI().protect(json.dumps(seal).encode("utf-8")))
    target = directory/(approval_id+".approval.json")
    write_new(target, json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
    print("[LAB] 두 실제 Windows 계정의 직접 동의 등록 완료. 승인은 1시간·1회·단일 항목에만 유효합니다.")
    quoted = str(target).replace("'", "''")
    quoted_root = str(ROOT).replace("'", "''")
    print(f"Set-Location -LiteralPath '{quoted_root}'")
    print(f"python scripts/lab_hardening_e2e.py --code {code} --approval-file '{quoted}'")
    print("위 사전 검증 통과 후에만 같은 명령에 --execute를 추가하십시오. 기존 실행 승인 절차는 그대로 적용됩니다.")
    return target


def verify_registration(data):
    approval_id = str(UUID(data["approval_id"]))
    for approval in data["approvers"]:
        policy.require(approval["reference"] == PREFIX+approval_id+":"+approval["role"], "REGISTRATION_REFERENCE_MISMATCH")
    path = folder()/(approval_id+".audit.jsonl")
    sealed = folder()/(approval_id+".audit.dpapi")
    for file in (path, sealed):
        policy.reject_reparse(file)
        policy.require(file.is_file() and file.stat().st_size <= 65536, "REGISTRATION_EVIDENCE_INVALID")
    raw = path.read_bytes()
    seal = json.loads(DPAPI().unprotect(sealed.read_bytes()).decode("utf-8"))
    policy.require(seal == {"approval_id": approval_id, "approval_sha256": digest(data),
                            "audit_sha256": hashlib.sha256(raw).hexdigest(), "kind": "NATIVE_WINDOWS_LOGON"},
                   "REGISTRATION_SEAL_INVALID")
    events = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    policy.require([row["event"] for row in events] == ["REQUEST_CREATED", "ADMINISTRATOR_ACCEPTED",
                                                       "TEST_OWNER_ACCEPTED", "APPROVAL_COMPLETED"], "REGISTRATION_AUDIT_INCOMPLETE")
    policy.require(all(row["kind"] == "NATIVE_WINDOWS_LOGON" and row["approval_id"] == approval_id for row in events), "REGISTRATION_NOT_NATIVE")
    for row, approval in zip(events[1:3], data["approvers"]):
        policy.require(row["sid"] == approval["sid"] and row["approved_at"] == approval["approved_at"], "REGISTRATION_IDENTITY_MISMATCH")
    policy.require(events[2]["authentication"] == "WINDOWS_PIPE_TOKEN", "REGISTRATION_LOGON_UNVERIFIED")
    policy.require(events[0]["vm_uuid"] == data["vm_uuid"] and events[0]["commit"] == data["commit"]
                   and events[0]["code"] == data["code"] and events[0]["snapshot_id"] == data["snapshot"]["id"]
                   and events[-1]["approval_sha256"] == digest(data), "REGISTRATION_SCOPE_MISMATCH")
    times = [policy.utc(row["time"]) for row in events]
    policy.require(times == sorted(times) and policy.utc(data["issued_at"]) <= times[0]
                   and times[-1] < policy.utc(data["expires_at"]), "REGISTRATION_CLOCK_INVALID")


def main(argv=None):
    parser = argparse.ArgumentParser(description="실제 Windows 계정별 신규 LAB 위험 수용 등록; 하드닝 실행 없음")
    parser.add_argument("--code", choices=sorted(policy.e2e.SEMI_AUTO_ALLOWLIST), default="W-07")
    parser.add_argument("--snapshot-id", required=True)
    args = parser.parse_args(argv)
    try:
        register(args.code, args.snapshot_id)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, policy.LabRejected) else getattr(exc, "reason_code", type(exc).__name__)
        print(f"[LAB 승인 미발급] {reason}; 하드닝 미실행")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
