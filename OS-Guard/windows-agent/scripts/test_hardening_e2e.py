"""격리 Server 2022 VM 전용: 한 항목 준비·승인·조치·원복·원본 복구."""

import argparse
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
from agent.hardening.policy_actions import PolicyTransactionAction, require_local_policy
from agent.hardening.runner import _is_administrator

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
    code = parser.parse_args(argv).code
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
        except Exception:
            print("[SKIP] Server 2022/도메인/GPO 안전성 확인 불가; 변경 없음")
            return 1
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
