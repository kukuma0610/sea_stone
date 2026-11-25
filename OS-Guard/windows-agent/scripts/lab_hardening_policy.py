"""LAB-E2E-1: 격리 VM의 단일 시험에만 적용하는 위험 수용 정책.

PolicyOverdue의 의미를 확정하지 않는다. 운영 검사는 수정하지 않으며, 책임자가
발급한 승인 기록을 현장 관리자가 확인하는 로컬 시험 절차다. 기존 SID 기록 방식과
별도 신뢰 확인된 인증서의 CMS 방식은 구분하며, 어느 쪽도 Central 승인은 아니다.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from uuid import UUID

from agent.central.storage import reject_reparse, restrict_acl
from agent.checks.common import NativeWindowsReadOnlyApi
from scripts import test_hardening_e2e as e2e
from scripts.gpo_live_diagnostics import diagnose

ROOT = Path(__file__).resolve().parents[1]
RISK = "POLICY_OVERDUE_MEANING_UNVERIFIED"


class LabRejected(ValueError):
    pass


class ApprovalFieldsRejected(LabRejected):
    def __init__(self, issues):
        self.issues = issues
        super().__init__("APPROVAL_FIELDS_INVALID")


def require(condition, reason):
    if not condition:
        raise LabRejected(reason)


def utc(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "APPROVAL_TIME_INVALID")
    return result


def identity():
    query = r"""
$ErrorActionPreference='Stop'
$p=Get-CimInstance Win32_ComputerSystemProduct
$c=Get-CimInstance Win32_ComputerSystem
ConvertTo-Json -InputObject @([pscustomobject]@{
 uuid=[string]$p.UUID; manufacturer=[string]$c.Manufacturer; model=[string]$c.Model
 sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}) -Compress
"""
    rows = NativeWindowsReadOnlyApi()._run_powershell_json(query)
    require(len(rows) == 1, "VM_IDENTITY_UNVERIFIED")
    value = rows[0]
    require(value["manufacturer"] == "VMware, Inc." and "VMware" in value["model"], "NOT_VMWARE_VM")
    value["uuid"] = str(UUID(value["uuid"]))
    require(UUID(value["uuid"]).int not in {0, (1 << 128)-1}, "VM_UUID_UNVERIFIED")
    return value


def source_commit():
    def git(*args):
        return subprocess.check_output(["git", "-C", str(ROOT), *args], stderr=subprocess.DEVNULL,
                                       text=True).strip()
    commit = git("rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "COMMIT_UNVERIFIED")
    require(not git("diff", "HEAD", "--name-only"), "TRACKED_SOURCE_CHANGED")
    require(not any(Path(name).suffix.lower() in {".py", ".pyd", ".dll"}
                    for name in git("ls-files", "--others", "--exclude-standard", "agent", "scripts").splitlines()),
            "UNTRACKED_EXECUTABLE_SOURCE")
    # 미커밋 시험 실행기로 기존 커밋의 승인을 사용하는 것을 거부한다.
    for relative in ("scripts/lab_hardening_policy.py", "scripts/lab_hardening_e2e.py"):
        git("ls-files", "--error-unmatch", relative)
    return commit


def approval_field_issues(data):
    """파싱 실패는 경로·사유만 반환한다. 입력값/승인자 이름/SID는 출력하지 않는다."""
    issues = []
    if not isinstance(data, dict):
        return [("$", "OBJECT_REQUIRED")]
    expected = {"policy_version", "approval_id", "vm_uuid", "commit", "code", "max_uses",
                "issued_at", "expires_at", "isolated_vm", "no_operating_data_or_credentials",
                "risk", "snapshot", "approvers"}
    issues.extend((field, "FIELD_REQUIRED") for field in sorted(expected-set(data)))
    if set(data)-expected:
        issues.append(("$", "UNSUPPORTED_FIELDS"))
    for field in ("approval_id", "vm_uuid"):
        try:
            UUID(data.get(field))
        except (ValueError, TypeError, AttributeError):
            issues.append((field, "UUID_REQUIRED"))
    if not isinstance(data.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", data["commit"]):
        issues.append(("commit", "FULL_GIT_COMMIT_REQUIRED"))
    for field in ("issued_at", "expires_at"):
        try:
            utc(data.get(field))
        except (ValueError, TypeError, AttributeError):
            issues.append((field, "ISO8601_WITH_TIMEZONE_REQUIRED"))
    for field in ("isolated_vm", "no_operating_data_or_credentials"):
        if data.get(field) is not True:
            issues.append((field, "ATTESTATION_REQUIRED"))
    snapshot = data.get("snapshot")
    if not isinstance(snapshot, dict):
        issues.append(("snapshot", "OBJECT_REQUIRED"))
    else:
        for field in ("id", "recovery_procedure"):
            if not isinstance(snapshot.get(field), str) or not snapshot[field].strip():
                issues.append(("snapshot."+field, "TEXT_REQUIRED"))
        if snapshot.get("confirmed") is not True:
            issues.append(("snapshot.confirmed", "SNAPSHOT_ATTESTATION_REQUIRED"))
    approvals = data.get("approvers")
    if not isinstance(approvals, list) or len(approvals) != 2:
        issues.append(("approvers", "TWO_APPROVALS_REQUIRED"))
    else:
        for index, approval in enumerate(approvals):
            prefix = f"approvers[{index}]"
            if not isinstance(approval, dict):
                issues.append((prefix, "OBJECT_REQUIRED"))
                continue
            try:
                utc(approval.get("approved_at"))
            except (ValueError, TypeError, AttributeError):
                issues.append((prefix+".approved_at", "ISO8601_WITH_TIMEZONE_REQUIRED"))
            if approval.get("accepted") is not True:
                issues.append((prefix+".accepted", "EXPLICIT_RISK_APPROVAL_REQUIRED"))
            if not isinstance(approval.get("reference"), str) or not approval["reference"].strip():
                issues.append((prefix+".reference", "ACTUAL_APPROVAL_REFERENCE_REQUIRED"))
            if approval.get("method") == "DETACHED_CMS_SHA256":
                for field in ("document_file", "signature_file"):
                    if not isinstance(approval.get(field), str) or not approval[field].strip():
                        issues.append((prefix+"."+field, "EVIDENCE_FILE_REQUIRED"))
                if not isinstance(approval.get("document_sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", approval["document_sha256"]):
                    issues.append((prefix+".document_sha256", "SHA256_REQUIRED"))
            else:
                if not isinstance(approval.get("sid"), str) or not re.fullmatch(r"S-1-\d+(?:-\d+)+", approval["sid"]):
                    issues.append((prefix+".sid", "WINDOWS_SID_OR_EXTERNAL_SIGNATURE_REQUIRED"))
    return issues


def validate_approval(data, *, code, vm, commit, now=None, external_proof=None):
    issues = approval_field_issues(data)
    if issues:
        raise ApprovalFieldsRejected(issues)
    try:
        return _validate_approval(data, code=code, vm=vm, commit=commit, now=now, external_proof=external_proof)
    except ApprovalFieldsRejected:
        raise
    except LabRejected as exc:
        field = {"VM_BINDING_MISMATCH": "vm_uuid", "COMMIT_BINDING_MISMATCH": "commit",
                 "RISK_NOT_ACKNOWLEDGED": "risk/policy_version",
                 "CODE_BINDING_MISMATCH": "code", "SINGLE_USE_REQUIRED": "max_uses",
                 "APPROVAL_EXPIRED_OR_INVALID": "issued_at/expires_at",
                 "SNAPSHOT_NOT_ATTESTED": "snapshot", "SNAPSHOT_RECORD_INVALID": "snapshot",
                 "ADMINISTRATOR_BINDING_MISMATCH": "approvers.ADMINISTRATOR.sid",
                 "DISTINCT_APPROVERS_REQUIRED": "approvers", "RISK_APPROVAL_MISSING": "approvers",
                 "APPROVAL_REFERENCE_MISSING": "approvers.reference",
                 "ISOLATION_NOT_ATTESTED": "isolated_vm/no_operating_data_or_credentials"}.get(str(exc), "$")
        raise ApprovalFieldsRejected([(field, str(exc))]) from None
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ApprovalFieldsRejected([("$", "APPROVAL_SCHEMA_INVALID")]) from None


def _validate_approval(data, *, code, vm, commit, now=None, external_proof=None):
    now = now or datetime.now(timezone.utc)
    require(isinstance(data, dict) and set(data) == {
        "policy_version", "approval_id", "vm_uuid", "commit", "code", "max_uses",
        "issued_at", "expires_at", "isolated_vm", "no_operating_data_or_credentials",
        "risk", "snapshot", "approvers"}, "APPROVAL_SCHEMA_INVALID")
    require(data["policy_version"] == "LAB-E2E-1" and data["risk"] == RISK, "RISK_NOT_ACKNOWLEDGED")
    require(UUID(data["approval_id"]).int != 0, "APPROVAL_ID_INVALID")
    require(str(UUID(data["vm_uuid"])) == vm["uuid"], "VM_BINDING_MISMATCH")
    require(data["commit"] == commit, "COMMIT_BINDING_MISMATCH")
    require(code in e2e.SEMI_AUTO_ALLOWLIST and data["code"] == code, "CODE_BINDING_MISMATCH")
    require(type(data["max_uses"]) is int and data["max_uses"] == 1, "SINGLE_USE_REQUIRED")
    require(data["isolated_vm"] is True and data["no_operating_data_or_credentials"] is True,
            "ISOLATION_NOT_ATTESTED")
    issued, expires = utc(data["issued_at"]), utc(data["expires_at"])
    require(issued <= now < expires and timedelta(0) < expires-issued <= timedelta(hours=4), "APPROVAL_EXPIRED_OR_INVALID")
    snapshot = data["snapshot"]
    require(isinstance(snapshot, dict) and set(snapshot) == {"id", "confirmed", "recovery_procedure"}, "SNAPSHOT_RECORD_INVALID")
    require(snapshot["confirmed"] is True and isinstance(snapshot["id"], str) and 0 < len(snapshot["id"]) <= 200
            and snapshot["id"].isprintable()
            and isinstance(snapshot["recovery_procedure"], str) and 0 < len(snapshot["recovery_procedure"]) <= 2000,
            "SNAPSHOT_NOT_ATTESTED")
    approvals = data["approvers"]
    require(isinstance(approvals, list) and len(approvals) == 2, "TWO_APPROVALS_REQUIRED")
    require({a.get("role") for a in approvals} == {"ADMINISTRATOR", "TEST_OWNER"}, "APPROVAL_ROLES_INVALID")
    owner = next(a for a in approvals if a["role"] == "TEST_OWNER")
    external = owner.get("method") == "DETACHED_CMS_SHA256"
    if not external:
        require(len({a.get("sid") for a in approvals}) == 2, "DISTINCT_APPROVERS_REQUIRED")
    for approval in approvals:
        if approval is owner and external:
            require(set(approval) == {"role", "method", "accepted", "approved_at", "reference",
                                     "document_file", "document_sha256", "signature_file"}, "APPROVER_SCHEMA_INVALID")
        else:
            require(set(approval) == {"role", "sid", "accepted", "approved_at", "reference"}, "APPROVER_SCHEMA_INVALID")
            require(isinstance(approval["sid"], str) and re.fullmatch(r"S-1-\d+(?:-\d+)+", approval["sid"]), "APPROVER_SID_INVALID")
        require(approval["accepted"] is True and issued <= utc(approval["approved_at"]) <= now, "RISK_APPROVAL_MISSING")
        require(isinstance(approval["reference"], str) and 0 < len(approval["reference"]) <= 300, "APPROVAL_REFERENCE_MISSING")
        if approval["role"] == "ADMINISTRATOR":
            require(approval["sid"] == vm["sid"], "ADMINISTRATOR_BINDING_MISMATCH")
    if external:
        from scripts.lab_owner_signature import verify_owner
        verify_owner(data, owner, external_proof)
    elif any(a["reference"].startswith("windows-logon-v1:") for a in approvals):
        from scripts.lab_approval_registration import verify_registration
        try:
            verify_registration(data)
        except Exception:
            raise LabRejected("WINDOWS_LOGON_REGISTRATION_INVALID") from None
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def describe_gpo_list(winreg, key, info, *, depth=0, budget=None):
    """차단 원인용 제한 진단. 알려지지 않은 문자열/바이너리 내용은 출력하지 않는다."""
    budget = budget if budget is not None else [64]
    subkeys, values, _ = info
    print(f"[LAB GPO-List] depth={depth} subkeys={subkeys} values={values}; 적용 GPO 수가 아닌 Registry 객체 수")
    for index in range(min(values, max(0, budget[0]))):
        budget[0] -= 1
        name, value, kind = winreg.EnumValue(key, index)
        label = name if re.fullmatch(r"[A-Za-z0-9_-]{0,64}", name) else "[MASKED_NAME]"
        safe_text = isinstance(value, str) and value in {"", "Local", "LocalGPO", "Local Group Policy"}
        safe_number = (type(value) is int and name.casefold() in {
            "version", "options", "enabled", "accessdenied", "gpolink", "nooverride", "flags", "filterallowed"})
        display = value if safe_text or safe_number else "[MASKED]"
        type_name = {winreg.REG_SZ: "REG_SZ", winreg.REG_DWORD: "REG_DWORD",
                     winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ", winreg.REG_MULTI_SZ: "REG_MULTI_SZ"}.get(kind, str(kind))
        print(f"[LAB GPO-List value] name={label!r} type={type_name} data={display!r}")
    for index in range(min(subkeys, max(0, budget[0]))):
        budget[0] -= 1
        name = winreg.EnumKey(key, index)
        label = name if re.fullmatch(r"[0-9]{1,4}|\{?[0-9a-fA-F-]{36}\}?", name) else "[MASKED_KEY]"
        print(f"[LAB GPO-List key] name={label!r}; 객체 존재만으로 적용/미적용을 판정하지 않음")
        if depth < 2 and budget[0] > 0:
            with winreg.OpenKey(key, name, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as child:
                describe_gpo_list(winreg, child, winreg.QueryInfoKey(child), depth=depth+1, budget=budget)


def verify_gpo_list_state(winreg, state):
    # OpenKey의 부재와 열거 중 삭제/조회 실패를 구분한다. 후자는 허용하지 않는다.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, state, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        print("[LAB GPO-List] key absent")
        return
    with key:
        before = winreg.QueryInfoKey(key)
        subkeys, values, _ = before
        empty = subkeys == 0 and values == 0
        # 기존 운영용 verify_no_policy_history()와 동일한 '빈 기본값' 의미만 허용한다.
        # LocalGPO 하위 객체, 이름 있는 값, DWORD 0 등을 자동 미적용으로 해석하지 않는다.
        empty_default = (subkeys == 0 and values == 1
                         and winreg.EnumValue(key, 0) == ("", "", winreg.REG_SZ))
        if not (empty or empty_default):
            try:
                describe_gpo_list(winreg, key, before)
            except Exception as exc:
                print(f"[LAB GPO-List] diagnostic failed: {type(exc).__name__}; 차단 유지")
            raise LabRejected("LAB_GPO_LIST_NOT_EMPTY")
        require(winreg.QueryInfoKey(key) == before, "LAB_GPO_LIST_CHANGED_DURING_QUERY")
        print(f"[LAB GPO-List] verified empty; empty_default={empty_default}; 실제 적용 여부는 별도 라이브/RSOP/파일 검사")


def exact_history():
    import winreg
    history = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History"
    state = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, history, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        subkeys, values, _ = winreg.QueryInfoKey(key)
        require(subkeys == 0 and values == 1, "LAB_HISTORY_SHAPE_CHANGED")
        name, value, kind = winreg.EnumValue(key, 0)
        require(name == "PolicyOverdue" and kind == winreg.REG_DWORD and type(value) is int and value == 0,
                "LAB_HISTORY_VALUE_CHANGED")
    verify_gpo_list_state(winreg, state)


def environment():
    require(e2e._is_administrator(), "ADMINISTRATOR_REQUIRED")
    diagnose()  # 현재 부팅의 라이브 컴퓨터/사용자 정책 세션을 매번 확인한다.
    try:
        e2e.require_local_policy()
    except e2e.EnvironmentDiagnosticError as exc:
        require(exc.reason_code == "POLICY_HISTORY_FOUND" and
                getattr(exc, "history_detail", None) == "POLICY_OVERDUE_SEMANTICS_UNVERIFIED",
                "NON_EXEMPT_ENVIRONMENT_FAILURE")
        print("[LAB 환경] 운영 POLICY_HISTORY_FOUND 유지; 제한 시험 후보의 별도 GPO-List 검증 진행")
    else:
        raise LabRejected("LAB_EXCEPTION_NOT_APPLICABLE")
    # 기존 검사가 첫 History 경로에서 중단했으므로 두 번째 경로까지 독립 재확인한다.
    exact_history()
    print("[LAB 환경] 제한 시험 환경 조건 확인; 승인 등록/실행 허용은 별도 검증")


class Lease:
    """한 번 소비한 승인은 재사용 불가. 비정상 종료/원복 실패의 전역 잠금은 자동 해제하지 않는다."""
    def __init__(self, approval, digest):
        self.approval, self.digest = approval, digest
        self.folder = lab_state_root()
        self.lock = self.folder / "ACTIVE_OR_RECOVERY_REQUIRED"

    def acquire(self):
        reject_reparse(self.folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        restrict_acl(self.folder)
        with self.lock.open("x", encoding="utf-8") as stream:
            stream.write(self.approval["approval_id"])
            stream.flush()
            os.fsync(stream.fileno())
        try:
            used = self.folder / (str(UUID(self.approval["approval_id"])) + ".used")
            with used.open("x", encoding="utf-8") as stream:
                stream.write(self.digest)
                stream.flush()
                os.fsync(stream.fileno())
            archived = self.folder / (str(UUID(self.approval["approval_id"])) + ".approval.json")
            with archived.open("x", encoding="utf-8") as stream:
                json.dump(self.approval, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            self.lock.unlink()
            raise

    def release(self):
        require(self.lock.read_text(encoding="utf-8") == self.approval["approval_id"], "LAB_LOCK_CHANGED")
        self.lock.unlink()


def lab_state_root():
    # 저장소를 다른 폴더에 복제해도 1회 소비/전체 중단 잠금을 공유한다.
    # Known Folder API를 사용하며 임의 환경변수나 외부 경로는 받지 않는다.
    from agent.windows_service.security import known_roots
    _, data = known_roots()
    return data.parent / "OS Guard Lab E2E"
