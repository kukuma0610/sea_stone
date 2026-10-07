"""격리 Server 2022 VM 전용: 한 항목 준비·승인·조치·원복·원본 복구."""

import argparse
import ctypes
from dataclasses import asdict, replace
from copy import deepcopy
import sys
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agent.windows_checks import collect_check
from agent.hardening import ApprovalGate, HardeningRunner, HardeningState, SEMI_AUTO_ALLOWLIST, SnapshotStore, create_plan
from agent.hardening.models import PolicySnapshot
from agent.hardening.registry import get_action
from agent.hardening.actions import RegistryValueAction
from agent.hardening.policy_actions import (
    PolicyTransactionAction, PolicySafetyError, verify_local_gpo_files, system_executable,
)
from agent.hardening.runner import _is_administrator
from agent.checks.common import NativeWindowsReadOnlyApi


class EnvironmentDiagnosticError(PolicySafetyError):
    def __init__(self, reason_code, location, message):
        self.reason_code = reason_code
        self.location = location
        super().__init__(message)


def report_environment_exception(exc, reason_code, location):
    if not hasattr(exc, "reason_code"):
        exc.reason_code = reason_code
    if not hasattr(exc, "location"):
        exc.location = location
    print(f"[환경 실패] reason_code={getattr(exc, 'reason_code', reason_code)} "
          f"location={getattr(exc, 'location', location)} "
          f"exception={type(exc).__name__} message={exc}")


def collect_environment():
    # 고정 읽기 전용 CIM 조회: Caption/Domain/gpresult 표시 문자열을 해석하지 않는다.
    script = r"""
$location = 'OS_CIM'
$os = $null
$computer = $null
$diagnosticError = $null
$state = 'not_queried'
$gpos = @()
try {
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$location = 'COMPUTER_CIM'
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$location = 'GPO_CIM'
$state = 'verified'
$gpos = @()
try {
  $gpos = @(Get-CimInstance -Namespace root\RSOP\Computer -ClassName RSOP_GPO -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ id = [string]$_.id } })
} catch {
  if ($_.Exception -is [Microsoft.Management.Infrastructure.CimException] -and
      $_.Exception.StatusCode -eq [Microsoft.Management.Infrastructure.CimStatusCode]::InvalidNamespace) {
    $state = 'namespace_absent'
  } else { throw }
}
} catch {
  $diagnosticError = [pscustomobject]@{
    location = $location; message = [string]$_.Exception.Message
    exception_type = $_.Exception.GetType().FullName
  }
}
$data = @([pscustomobject]@{
  version = [string]$os.Version; build = [string]$os.BuildNumber
  product_type = [int]$os.ProductType; domain_joined = $computer.PartOfDomain
  domain_role = [int]$computer.DomainRole; gpo_state = $state; gpos = @($gpos)
  diagnostic_error = $diagnosticError
})
ConvertTo-Json -InputObject $data -Depth 4 -Compress
"""
    try:
        rows = NativeWindowsReadOnlyApi()._run_powershell_json(script)
    except Exception as exc:
        report_environment_exception(exc, "CIM_QUERY_FAILED", "CIM_TRANSPORT")
        raise
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise EnvironmentDiagnosticError("CIM_QUERY_FAILED", "CIM_JSON", "structured environment query failed")
    error = rows[0].get("diagnostic_error")
    if error:
        print(f"[환경] 부분 수집: version={rows[0].get('version')} build={rows[0].get('build')} "
              f"ProductType={rows[0].get('product_type')} PartOfDomain={rows[0].get('domain_joined')} "
              f"GPO={rows[0].get('gpo_state')} (조회 실패: 적용 개수 미확인)")
        reason = "GPO_QUERY_FAILED" if error["location"] == "GPO_CIM" else "CIM_QUERY_FAILED"
        raise EnvironmentDiagnosticError(reason, error["location"],
                                         f"{error['exception_type']}: {error['message']}")
    return rows[0]


def verify_no_policy_history():
    import winreg
    # RSoP namespace가 없더라도 정책 적용 이력이 남은 장비는 허용하지 않는다.
    for path in (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List",
    ):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                subkeys, values, _ = winreg.QueryInfoKey(key)
                print(f"[환경] 정책 이력 {path}: subkeys={subkeys}, values={values}")
                if subkeys or values:
                    raise EnvironmentDiagnosticError("POLICY_HISTORY_FOUND", "POLICY_HISTORY", "policy history is present or cannot be resolved")
        except FileNotFoundError:
            print(f"[환경] 정책 이력 {path}: 없음")


def require_local_policy():
    # E2E 전용 검사. 제품 Hardening의 정책 검사 함수는 변경하지 않는다.
    info = collect_environment()
    print(f"[환경] OS 판정 입력: Version={info.get('version')}, Build={info.get('build')}, "
          f"ProductType={info.get('product_type')}, Python bits={ctypes.sizeof(ctypes.c_void_p) * 8}")
    print(f"[환경] PartOfDomain={info.get('domain_joined')}, DomainRole={info.get('domain_role')}")
    print(f"[환경] GPO 조회={info.get('gpo_state')}, 적용 GPO 개수="
          f"{len(info['gpos']) if isinstance(info.get('gpos'), list) else '미확인'}")
    if (info.get("version") != "10.0.20348" or str(info.get("build")) != "20348"
            or type(info.get("product_type")) is not int or info["product_type"] != 3
            or ctypes.sizeof(ctypes.c_void_p) != 8):
        raise EnvironmentDiagnosticError("NOT_SERVER_2022", "OS_VALIDATION", "64-bit Windows Server 2022 could not be verified")
    print("[환경] OS 판정: PASS")
    if info.get("domain_joined") is not False or type(info.get("domain_role")) is not int or info["domain_role"] != 2:
        reason = "DOMAIN_JOINED" if info.get("domain_joined") is True else "DOMAIN_STATE_UNVERIFIED"
        raise EnvironmentDiagnosticError(reason, "DOMAIN_VALIDATION", "standalone non-domain server could not be verified")
    gpos = info.get("gpos")
    if not isinstance(gpos, list) or any(
        not isinstance(gpo, dict) or gpo.get("id") != "LocalGPO" for gpo in gpos
    ):
        raise EnvironmentDiagnosticError("APPLIED_GPO_FOUND" if isinstance(gpos, list) else "GPO_QUERY_FAILED", "GPO_VALIDATION", "non-local or unknown GPO is present")
    if info.get("gpo_state") not in {"verified", "namespace_absent"}:
        raise EnvironmentDiagnosticError("GPO_QUERY_FAILED", "GPO_VALIDATION", "GPO query is unverified")
    if info["gpo_state"] == "namespace_absent" and gpos:
        raise EnvironmentDiagnosticError("GPO_QUERY_FAILED", "GPO_VALIDATION", "inconsistent GPO query")
    try:
        verify_local_gpo_files(Path(system_executable("gpresult.exe")).parent)
        print("[환경] Local Group Policy 파일 검사: PASS")
    except Exception as exc:
        report_environment_exception(exc, "LOCAL_GPO_CHECK_FAILED", "LOCAL_GPO_FILES")
        raise
    try:
        verify_no_policy_history()
        print("[환경] 정책 이력 검사: PASS")
    except Exception as exc:
        report_environment_exception(exc, "POLICY_HISTORY_CHECK_FAILED", "POLICY_HISTORY")
        raise

FAIL_VALUES = {
    "W-07": 1, "W-13": 0, "W-15": 0, "W-48": 1,
    "W-50": 1, "W-52": "1", "W-53": "1", "W-59": 2,
}
POLICY_FAIL_VALUES = {
    "W-04": {"LockoutBadCount": 6},
    "W-05": {"ClearTextPassword": 1},
    "W-08": {"ResetLockoutCount": 30, "LockoutDuration": 30},
    "W-09": {"PasswordComplexity": 0},
    "W-10": {"DontDisplayLastUserName": 0},
    "W-12": {"LSAAnonymousNameLookup": 1},
    "W-28": {"MinEncryptionLevel": 1},
    "W-36": {"MaxIdleTime": 3600000},
    "W-49": {"SeRemoteShutdownPrivilege": ["S-1-5-32-544", "S-1-5-32-545"]},
    "W-55": {"AddPrinterDrivers": 0},
}

def expected_setting(snapshot):
    if isinstance(snapshot, PolicySnapshot):
        return {"targets": snapshot.targets}
    return {"exists": snapshot.existed, "value": snapshot.previous_value,
            "registry_type": snapshot.value_type}

def prepare_fail(action, original):
    # 외부 경로·값·명령은 받지 않고 선택한 고정 action의 대상만 변경한다.
    if isinstance(action, RegistryValueAction):
        replace(action, target_value=FAIL_VALUES[action.code]).apply()
        return
    if not isinstance(action, PolicyTransactionAction):
        raise RuntimeError("unsupported test action")
    entries = deepcopy(original["targets"])
    action.validate(entries)
    by_name = {entry["name"]: entry for entry in entries}
    targets = {target.key: target for target in action.targets}
    for name, value in POLICY_FAIL_VALUES[action.code].items():
        target = targets[name]
        entry = {**by_name[name], "exists": True, "value": value,
                 "type": 4 if target.path else by_name[name]["type"]}
        action.validate([entry if old["name"] == name else old for old in entries])
        action.backend.write(target, entry)

def main(argv=None):
    parser = argparse.ArgumentParser(description="격리 VM 전용 단일 SEMI_AUTO E2E; 원본 최종 복구")
    parser.add_argument("--code", required=True, choices=sorted(SEMI_AUTO_ALLOWLIST))
    parser.add_argument("--diagnose-env", action="store_true", help="읽기 전용 환경 검사 후 종료; CHECK/백업/설정 변경 없음")
    args = parser.parse_args(argv)
    code = args.code
    store = SnapshotStore(PROJECT_ROOT / "results" / "hardening-snapshots")
    originals = SnapshotStore(PROJECT_ROOT / "results" / "hardening-e2e" / "originals")
    original_snapshot = None
    preparation_started = False
    outcome = 1
    step = "환경 확인"
    try:
        if not _is_administrator():
            print("[거부] 관리자 권한 필요; 변경 없음")
            return 1
        try:
            require_local_policy()
        except Exception as exc:
            report_environment_exception(exc, "ENVIRONMENT_CHECK_FAILED", "ENVIRONMENT")
            print(f"[SKIP] reason_code={getattr(exc, 'reason_code', 'ENVIRONMENT_CHECK_FAILED')}; 변경 없음")
            return 1
        if args.diagnose_env:
            print("[환경 검사 완료] PASS; 진단 전용, 변경 없음")
            return 0
        print("[주의] 격리 VM 전용. 한 항목만 변경하고 종료 시 원본을 복구합니다.")
        if input(f"격리 VM임을 확인하고 FAIL 준비·최종 복구를 승인하려면 PREPARE {code} 입력: ").strip() != f"PREPARE {code}":
            print("[중단] 테스트 준비 미승인; 변경 없음")
            return 1
        action = get_action(code)
        original_check = collect_check(code)
        original_status = original_check.status
        if code == "W-28" and original_check.current_value.get("service_running") is False:
            print("[SKIP] RDP 미실행: 서비스를 시작하지 않으므로 FAIL 준비 불가")
            return 1
        step = "1. 원본 백업"
        original = action.capture()
        save = originals.create_transaction if isinstance(action, PolicyTransactionAction) else originals.create
        saved = save(code=code, plan_id="e2e-" + str(uuid4()), path=action.path,
                     value_name=action.name, captured=original)
        original_snapshot = originals.load(saved.snapshot_id)
        if expected_setting(original_snapshot) != original:
            raise RuntimeError("original backup verification failed")
        print(f"[성공] {step}: {originals.directory / (saved.snapshot_id + '.json')}")
        step = "2. FAIL 준비"
        require_local_policy()
        if action.capture() != original:
            raise RuntimeError("original settings changed before preparation")
        preparation_started = True
        prepare_fail(action, original)
        print(f"[성공] {step}: {code} 고정 테스트값 적용")
        step = "3. CHECK"
        observation = collect_check(code)
        if observation.status != "FAIL":
            raise RuntimeError("FAIL expected")
        prepared = action.capture()
        print(f"[성공] {step}: FAIL")
        step = "4. Plan 생성"
        plan = create_plan(observation)
        gate = ApprovalGate()
        waiting = gate.request(plan)
        print(f"[성공] {step}: SEMI_AUTO / WAITING_APPROVAL")
        step = "5. 명시적 승인"
        if input(f"하드닝을 승인하려면 APPROVE {code} 입력: ").strip() != f"APPROVE {code}":
            raise RuntimeError("hardening approval declined")
        approved, receipt = gate.approve(waiting, approved=True)
        print(f"[성공] {step}: APPROVED")
        step = "6. Hardening 실행"
        runner = HardeningRunner(gate, snapshot_store=store)
        result = runner.run(approved, receipt)
        if result.state is not HardeningState.SUCCESS:
            raise RuntimeError("hardening failed")
        print(f"[성공] {step}: SUCCESS")
        step = "7. 재CHECK"
        if collect_check(code).status != "PASS":
            raise RuntimeError("PASS expected")
        print(f"[성공] {step}: PASS")
        step = "8. Snapshot / Before / After 검증"
        snapshot = store.load(result.snapshot_id)
        if (snapshot.code != code or snapshot.plan_id != plan.plan_id
                or expected_setting(snapshot) != prepared
                or result.before["setting"] != prepared
                or result.after["setting"] != action.capture()
                or result.before["check"]["status"] != "FAIL"
                or result.after["check"]["status"] != "PASS"
                or not result.changed or not result.pass_transition):
            raise RuntimeError("hardening snapshot or result verification failed")
        print(f"[성공] {step}: 일치 / changed=True")
        step = "9. Hardening rollback"
        rollback = runner.rollback(code=code, snapshot_id=result.snapshot_id, plan_id=plan.plan_id)
        if not rollback.success or rollback.restored_setting != prepared:
            raise RuntimeError("prepared FAIL rollback failed")
        print(f"[성공] {step}: 준비값·타입 복원")
        step = "10. 준비 상태 CHECK"
        if collect_check(code).status != "FAIL":
            raise RuntimeError("prepared FAIL expected")
        print(f"[성공] {step}: FAIL")
        outcome = 0
    except (Exception, KeyboardInterrupt) as exc:
        print(f"[실패] {step}: {type(exc).__name__}")
    finally:
        if preparation_started and original_snapshot is not None:
            try:
                if not _is_administrator():
                    raise RuntimeError("administrator privileges lost")
                original_snapshot = originals.load(original_snapshot.snapshot_id)
                if (original_snapshot.code != code or original_snapshot.registry_path != action.path
                        or original_snapshot.value_name != action.name
                        or expected_setting(original_snapshot) != original):
                    raise RuntimeError("original backup identity or contents changed")
                action.restore(asdict(original_snapshot))
                print("[성공] 11. 테스트 전 원본 복구")
                if action.capture() != expected_setting(original_snapshot):
                    raise RuntimeError("original settings or types differ")
                if collect_check(code).status != original_status:
                    raise RuntimeError("original CHECK status differs")
                print(f"[성공] 12. 원본 값·타입·존재 여부 및 CHECK 상태 일치: {original_status}")
            except (Exception, KeyboardInterrupt) as exc:
                outcome = 1
                print(f"[원본 복구 실패] {type(exc).__name__}; 원본 백업 보존, 수동 복구 필요")
    if outcome == 0:
        print(f"[완료] {code}: 원본 → FAIL → PASS → FAIL → 원본 복구")
    return outcome

if __name__ == "__main__":
    raise SystemExit(main())
