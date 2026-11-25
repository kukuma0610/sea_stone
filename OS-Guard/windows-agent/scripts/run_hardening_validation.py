"""한 항목씩 기존 E2E를 호출하고 로컬 결과를 기록한다. 기본 동작은 읽기 전용이다."""

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import test_hardening_e2e as e2e


class ConsoleLog:
    def __init__(self, console, log):
        self.console, self.log = console, log

    def write(self, text):
        self.console.write(text)
        self.log.write(text)
        self.flush()
        return len(text)

    def flush(self):
        self.console.flush()
        self.log.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description="격리 VM 단일 항목 검증·기록; 기본은 진단만")
    parser.add_argument("--code", required=True, choices=sorted(e2e.SEMI_AUTO_ALLOWLIST))
    parser.add_argument("--execute", action="store_true", help="스냅샷 확인 및 기존 PREPARE/APPROVE 승인 후에만 E2E 실행")
    args = parser.parse_args(argv)
    if args.execute:
        print("격리 VM 스냅샷 확보 후에만 실행하십시오. 기존 E2E가 FAIL 설정을 준비합니다.")
        if input(f"스냅샷 확보 확인: SNAPSHOT {args.code} 입력: ").strip() != f"SNAPSHOT {args.code}":
            print("[중단] 스냅샷 확인 미승인; E2E 호출·설정 변경 없음")
            return 1
    directory = ROOT / "results" / "hardening-validation"
    directory.mkdir(parents=True, exist_ok=True)
    run_id = f"{args.code}-{uuid4()}"
    log_path, report_path = directory / f"{run_id}.log", directory / f"{run_id}.json"
    started = datetime.now(timezone.utc).isoformat()
    outcome = 1
    try:
        # 원문 계정/설정값은 수집하지 않는다. 기존 E2E의 안전한 단계 출력만 기록한다.
        with log_path.open("x", encoding="utf-8") as log, redirect_stdout(ConsoleLog(sys.stdout, log)):
            outcome = e2e.main(["--code", args.code, "--diagnose-env"])
            if args.execute and outcome == 0:
                # 이번 호출에서도 라이브 진단을 통과해야 기존 준비/승인 흐름으로 간다.
                outcome = e2e.main(["--code", args.code])
    finally:
        report = {"code": args.code, "mode": "E2E" if args.execute else "DIAGNOSE_ONLY",
                  "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
                  "exit_code": outcome, "result": "PASS" if outcome == 0 else "FAILED_OR_SKIPPED",
                  "console_log": str(log_path), "central_approval": False}
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
        print(f"[검증 기록] {report_path}")
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
