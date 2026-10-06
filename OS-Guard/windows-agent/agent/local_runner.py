"""Offline, read-only Windows CHECK runner for Server 2022 VM validation."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .windows_checks import CheckObservation, KISA_SOURCES, NativeWindowsReadOnlyApi, collect_check


CHECK_IDS = tuple(f"W-{number:02d}" for number in range(1, 65))
CHECK_TITLES = dict(zip(CHECK_IDS, (
    "Administrator 계정 이름 변경 등 보안성 강화", "Guest 계정 비활성화", "불필요한 계정 제거",
    "계정 잠금 임계값 설정", "해독 가능한 암호화를 사용하여 암호 저장 해제", "관리자 그룹에 최소한의 사용자 포함",
    "Everyone 사용 권한을 익명 사용자에게 적용", "계정 잠금 기간 설정", "비밀번호 관리정책 설정",
    "마지막 사용자 이름 표시 안 함", "로컬 로그온 허용", "익명 SID/이름 변환 허용 해제",
    "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한", "원격터미널 접속 가능한 사용자 그룹 제한",
    "사용자 개인키 사용 시 암호 입력", "공유 권한 및 사용자 그룹 설정", "하드디스크 기본 공유 제거",
    "불필요한 서비스 제거", "불필요한 IIS 서비스 구동 점검", "NetBIOS 바인딩 서비스 구동 점검",
    "암호화되지 않는 FTP 서비스 비활성화", "FTP 디렉토리 접근권한 설정", "공유 서비스에 대한 익명 접근 제한 설정",
    "FTP 접근 제어 설정", "DNS Zone Transfer 설정", "RDS(Remote Data Services) 제거",
    "최신 Windows OS Build 버전 적용", "터미널 서비스 암호화 수준 설정", "불필요한 SNMP 서비스 구동 점검",
    "SNMP Community String 복잡성 설정", "SNMP Access Control 설정", "DNS 서비스 구동 점검",
    "HTTP/FTP/SMTP 배너 차단", "Telnet 서비스 비활성화", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거",
    "원격터미널 접속 타임아웃 설정", "예약된 작업에 의심스러운 명령 등록 여부 점검",
    "주기적 보안 패치 및 벤더 권고사항 적용", "백신 프로그램 업데이트", "정책에 따른 시스템 로깅 설정",
    "NTP 및 시각 동기화 설정", "이벤트 로그 관리 설정", "이벤트 로그 파일 접근 통제 설정",
    "원격으로 액세스할 수 있는 레지스트리 경로", "백신 프로그램 설치", "SAM 파일 접근 통제 설정",
    "화면보호기 설정", "로그온하지 않고 시스템 종료 허용", "원격 시스템에서 강제로 시스템 종료",
    "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료", "SAM 계정과 공유의 익명 열거 허용 안 함",
    "Autologon 기능 제어", "이동식 미디어 포맷 및 꺼내기 허용", "DoS 공격 방어 레지스트리 설정",
    "사용자가 프린터 드라이버를 설치할 수 없게 함", "SMB 세션 중단 관리 설정", "로그온 시 경고 메시지 설정",
    "사용자별 홈 디렉터리 권한 설정", "LAN Manager 인증 수준", "보안 채널 데이터 디지털 암호화 또는 서명",
    "파일 및 디렉토리 보호", "시작프로그램 목록 분석", "도메인 컨트롤러-사용자의 시간 동기화",
    "윈도우 방화벽 설정",
)))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _system_info() -> dict[str, Any]:
    version = platform.win32_ver()
    return {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "windows_edition": version[0],
        "windows_build": version[1],
        "architecture": platform.machine(),
        "administrator": _is_administrator(),
    }


def _safe_error(exc: Exception) -> str:
    message = f"{type(exc).__name__}: {exc}"
    for value in (os.environ.get("USERNAME"), os.environ.get("USERPROFILE")):
        if value:
            message = message.replace(value, "***")
    return message


def _unexpected_failure(item_id: str, exc: Exception) -> CheckObservation:
    return CheckObservation(
        item_id=item_id,
        status="UNABLE",
        reason_code="LOCAL_RUNNER_UNEXPECTED_ERROR",
        current_value={},
        observed_at=_now(),
        source_page=KISA_SOURCES.get(item_id, {}).get("page"),
        manual_review_required=True,
        evidence_redacted=True,
        error_reason=_safe_error(exc),
    )


def run_checks(
    *,
    api: Any | None = None,
    collector: Callable[[str, Any | None], CheckObservation] = collect_check,
    system_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    info = system_info or _system_info()
    read_only_api = api
    api_error: Exception | None = None
    if read_only_api is None:
        try:
            read_only_api = NativeWindowsReadOnlyApi()
        except Exception as exc:  # Each item must still produce an UNABLE result.
            api_error = exc

    checks: list[dict[str, Any]] = []
    for item_id in CHECK_IDS:
        try:
            observation = (
                _unexpected_failure(item_id, api_error)
                if api_error is not None
                else collector(item_id, read_only_api)
            )
        except Exception as exc:  # Isolate an unexpected collector failure to one W-code.
            observation = _unexpected_failure(item_id, exc)
        record = asdict(observation)
        record["evidence"] = record.pop("current_value")
        checks.append(record)

    counts = {status: sum(check["status"] == status for check in checks) for status in ("PASS", "FAIL", "NA", "UNABLE")}
    return {"mode": "LOCAL_READ_ONLY", "generated_at": _now(), "system": info, "summary": counts, "checks": checks}


def save_report(report: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return output.resolve()


def _default_output() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("results") / f"windows-check-{stamp}.json"


CONSOLE_REASON_MAP = {
    "WINDOWS_API_UNAVAILABLE": "Windows 설정을 읽을 수 없습니다.",
    "LOCAL_RUNNER_UNEXPECTED_ERROR": "점검 중 예상하지 못한 오류가 발생했습니다.",
    "Effective domain password policy requires VM verification": "도메인 적용 정책은 서버에서 추가 확인이 필요합니다.",
    "FTP service running; no FTP sites collected; encryption cannot be verified": "FTP 서비스는 실행 중이지만 사이트가 없어 암호화 설정을 확인할 수 없습니다.",
    "No FTP sites available for directory permission verification": "FTP 사이트가 없어 디렉터리 권한을 확인할 수 없습니다.",
    "No FTP sites available for IP access control verification": "FTP 사이트가 없어 IP 접근 제어를 확인할 수 없습니다.",
    "Current-user settings do not verify all applicable user sessions": "현재 사용자 설정만으로 전체 사용자 적용 여부를 확인할 수 없습니다.",
    "collection failed": "설정 수집에 실패했습니다.",
    "command failed": "조회 명령 실행에 실패했습니다.",
}


def _console_reason(reason: Any) -> str:
    value = " ".join(str(reason).split())
    if value in CONSOLE_REASON_MAP:
        return CONSOLE_REASON_MAP[value]
    if value.startswith("KISA_W"):
        return "KISA 양호 기준을 충족하지 않습니다."
    if value.endswith("_REQUIRES_MANUAL_REVIEW"):
        return "운영 환경과 업무 필요성에 대한 수동 검토가 필요합니다."
    if value.endswith("_NOT_FOUND"):
        return "점검에 필요한 설정 또는 대상을 찾지 못했습니다."
    if value.endswith(("_NOT_DETERMINED", "_NOT_AVAILABLE")):
        return "점검에 필요한 설정값을 확인할 수 없습니다."
    if "registry value absent; effective default not verified" in value:
        return "레지스트리 값이 없고 실효 기본값을 확인할 수 없습니다."
    if "registry read failed" in value:
        return "레지스트리 설정을 읽지 못했습니다."
    if "security policy export failed" in value:
        return "로컬 보안 정책을 내보내지 못했습니다."
    if "access denied" in value.lower() or "ACCESS_DENIED" in value:
        return "권한이 부족하여 설정을 확인할 수 없습니다."
    return value


def _short_reason(check: dict[str, Any]) -> str:
    reason = check.get("error_reason") or check.get("reason_code") or "사유 없음"
    return _console_reason(reason)[:160]


def print_report(report: dict[str, Any], output: Path) -> None:
    system = report["system"]
    build = system.get("windows_build") or system.get("version") or "unknown"
    print(f"OS: {system.get('os', 'unknown')} {system.get('release', '')}".rstrip())
    print(f"Build: {build}")
    print(f"관리자: {'예' if system.get('administrator') else '아니요'}")
    print()
    for check in report["checks"]:
        item_id = check["item_id"]
        print(f"[{check['status']}] {item_id} {CHECK_TITLES[item_id]}")
        if check["status"] in {"FAIL", "UNABLE"}:
            print(f"  사유: {_short_reason(check)}")
    summary = report["summary"]
    print()
    print(
        "요약: "
        f"PASS={summary['PASS']} FAIL={summary['FAIL']} "
        f"UNABLE={summary['UNABLE']} NA={summary['NA']} TOTAL={len(report['checks'])}"
    )
    print(f"JSON: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run W-01 through W-64 locally without central API transmission")
    parser.add_argument("--output", type=Path, default=_default_output(), help="JSON report path")
    args = parser.parse_args()

    report = run_checks()
    output = save_report(report, args.output)
    print_report(report, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
