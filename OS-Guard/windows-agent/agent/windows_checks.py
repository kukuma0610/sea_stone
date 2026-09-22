import ctypes
import os
import platform
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any


_ITEMS = (
    ("W-01", "Administrator 계정 이름 변경 등 보안성 강화"),
    ("W-02", "Guest 계정 비활성화"),
    ("W-03", "불필요한 계정 제거"),
    ("W-04", "계정 잠금 임계값 설정"),
    ("W-05", "해독 가능한 암호화를 사용하여 암호 저장 해제"),
    ("W-06", "관리자 그룹에 최소한의 사용자 포함"),
    ("W-07", "Everyone 사용 권한을 익명 사용자에게 적용"),
    ("W-08", "계정 잠금 기간 설정"),
    ("W-09", "비밀번호 관리정책 설정"),
    ("W-10", "마지막 사용자 이름 표시 안 함"),
    ("W-11", "로컬 로그온 허용"),
    ("W-12", "익명 SID/이름 변환 허용 해제"),
    ("W-13", "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"),
    ("W-14", "원격터미널 접속 가능한 사용자 그룹 제한"),
    ("W-15", "사용자 개인키 사용 시 암호 입력"),
    ("W-16", "공유 권한 및 사용자 그룹 설정"),
    ("W-17", "하드디스크 기본 공유 제거"),
    ("W-18", "불필요한 서비스 제거"),
    ("W-19", "불필요한 IIS 서비스 구동 점검"),
    ("W-20", "NetBIOS 바인딩 서비스 구동 점검"),
    ("W-21", "암호화되지 않는 FTP 서비스 비활성화"),
    ("W-22", "FTP 디렉토리 접근권한 설정"),
    ("W-23", "공유 서비스에 대한 익명 접근 제한 설정"),
    ("W-24", "FTP 접근 제어 설정"),
    ("W-25", "DNS Zone Transfer 설정"),
    ("W-26", "RDS(Remote Data Services) 제거"),
    ("W-27", "최신 Windows OS Build 버전 적용"),
    ("W-28", "터미널 서비스 암호화 수준 설정"),
    ("W-29", "불필요한 SNMP 서비스 구동 점검"),
    ("W-30", "SNMP Community String 복잡성 설정"),
    ("W-31", "SNMP Access control 설정"),
    ("W-32", "DNS 서비스 구동 점검"),
    ("W-33", "HTTP/FTP/SMTP 배너 차단"),
    ("W-34", "Telnet 서비스 비활성화"),
    ("W-35", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거"),
    ("W-36", "원격터미널 접속 타임아웃 설정"),
    ("W-37", "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검"),
    ("W-38", "주기적 보안 패치 및 벤더 권고사항 적용"),
    ("W-39", "백신 프로그램 업데이트"),
    ("W-40", "정책에 따른 시스템 로깅 설정"),
    ("W-41", "NTP 및 시각 동기화 설정"),
    ("W-42", "이벤트 로그 관리 설정"),
    ("W-43", "이벤트 로그 파일 접근 통제 설정"),
    ("W-44", "원격으로 액세스할 수 있는 레지스트리 경로"),
    ("W-45", "백신 프로그램 설치"),
    ("W-46", "SAM 파일 접근 통제 설정"),
    ("W-47", "화면보호기 설정"),
    ("W-48", "로그온하지 않고 시스템 종료 허용"),
    ("W-49", "원격 시스템에서 강제로 시스템 종료"),
    ("W-50", "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료"),
    ("W-51", "SAM 계정과 공유의 익명 열거 허용 안 함"),
    ("W-52", "Autologon 기능 제어"),
    ("W-53", "이동식 미디어 포맷 및 꺼내기 허용"),
    ("W-54", "DoS 공격 방어 레지스트리 설정"),
    ("W-55", "사용자가 프린터 드라이버를 설치할 수 없게 함"),
    ("W-56", "SMB 세션 중단 관리 설정"),
    ("W-57", "로그온 시 경고 메시지 설정"),
    ("W-58", "사용자별 홈 디렉터리 권한 설정"),
    ("W-59", "LAN Manager 인증 수준"),
    ("W-60", "보안 채널 데이터 디지털 암호화 또는 서명"),
    ("W-61", "파일 및 디렉토리 보호"),
    ("W-62", "시작프로그램 목록 분석"),
    ("W-63", "도메인 컨트롤러-사용자의 시간 동기화"),
    ("W-64", "윈도우 방화벽 설정"),
)
WINDOWS_CHECKS = dict(_ITEMS)

KISA_SOURCES = {
    "W-01": {"page": 177, "good": "Administrator 기본 계정 이름 변경 또는 강화된 비밀번호", "bad": "기본 이름 미변경 또는 단순 비밀번호"},
    "W-02": {"page": 178, "good": "Guest 계정 비활성화", "bad": "Guest 계정 활성화"},
    "W-03": {"page": 179, "good": "불필요한 계정 없음", "bad": "불필요한 계정 존재"},
    "W-04": {"page": 180, "good": "계정 잠금 임계값 5 이하", "bad": "계정 잠금 임계값 5 초과"},
    "W-05": {"page": 181, "good": "해독 가능한 암호화를 사용하여 암호 저장: 사용 안 함", "bad": "해당 정책: 사용"},
}


@dataclass(frozen=True)
class CheckObservation:
    item_id: str
    status: str
    reason_code: str
    current_value: dict[str, Any]


class WindowsApiUnavailable(RuntimeError):
    pass


class _UserInfo23(ctypes.Structure):
    _fields_ = [
        ("name", wintypes.LPWSTR), ("password", wintypes.LPWSTR), ("password_age", wintypes.DWORD),
        ("priv", wintypes.DWORD), ("home_dir", wintypes.LPWSTR), ("comment", wintypes.LPWSTR),
        ("flags", wintypes.DWORD), ("script_path", wintypes.LPWSTR), ("auth_flags", wintypes.DWORD),
        ("full_name", wintypes.LPWSTR), ("parms", wintypes.LPWSTR), ("workstations", wintypes.LPWSTR),
        ("last_logon", wintypes.DWORD), ("last_logoff", wintypes.DWORD), ("acct_expires", wintypes.DWORD),
        ("max_storage", wintypes.DWORD), ("units_per_week", wintypes.DWORD), ("logon_hours", ctypes.POINTER(wintypes.BYTE)),
        ("bad_pw_count", wintypes.DWORD), ("num_logons", wintypes.DWORD), ("logon_server", wintypes.LPWSTR),
        ("country_code", wintypes.DWORD), ("code_page", wintypes.DWORD), ("user_id", wintypes.DWORD),
        ("primary_group_id", wintypes.DWORD), ("profile", wintypes.LPWSTR), ("home_dir_drive", wintypes.LPWSTR),
        ("password_expired", wintypes.DWORD), ("password_can_change", wintypes.DWORD), ("password_must_change", wintypes.DWORD),
    ]


class _UserModalsInfo3(ctypes.Structure):
    _fields_ = [("lockout_threshold", wintypes.DWORD), ("lockout_observation_window", wintypes.DWORD), ("lockout_duration", wintypes.DWORD)]


class NativeWindowsReadOnlyApi:
    """Small read-only NetAPI adapter; no subprocess or configuration API is used."""

    def __init__(self):
        if os.name != "nt":
            raise WindowsApiUnavailable("Windows Server API is unavailable on this host")
        self._netapi = ctypes.WinDLL("Netapi32.dll")

    def accounts(self) -> list[dict[str, Any]]:
        buffer = ctypes.c_void_p()
        entries_read = wintypes.DWORD()
        total_entries = wintypes.DWORD()
        resume = wintypes.DWORD()
        result: list[dict[str, Any]] = []
        try:
            while True:
                status = self._netapi.NetUserEnum(
                    None, 23, 0, ctypes.byref(buffer), wintypes.DWORD(-1),
                    ctypes.byref(entries_read), ctypes.byref(total_entries), ctypes.byref(resume),
                )
                if status not in (0, 234):
                    raise WindowsApiUnavailable(f"NetUserEnum failed: {status}")
                rows = ctypes.cast(buffer, ctypes.POINTER(_UserInfo23))
                for i in range(entries_read.value):
                    row = rows[i]
                    result.append({"name": row.name or "", "user_id": row.user_id, "disabled": bool(row.flags & 0x2)})
                self._netapi.NetApiBufferFree(buffer)
                buffer = ctypes.c_void_p()
                if status != 234:
                    break
        finally:
            if buffer.value:
                self._netapi.NetApiBufferFree(buffer)
        return result

    def lockout_threshold(self) -> int:
        buffer = ctypes.c_void_p()
        status = self._netapi.NetUserModalsGet(None, 3, ctypes.byref(buffer))
        if status != 0:
            raise WindowsApiUnavailable(f"NetUserModalsGet failed: {status}")
        try:
            return ctypes.cast(buffer, ctypes.POINTER(_UserModalsInfo3)).contents.lockout_threshold
        finally:
            self._netapi.NetApiBufferFree(buffer)


def collect_check(item_id: str, api: Any | None = None) -> CheckObservation:
    if item_id not in WINDOWS_CHECKS:
        raise ValueError("unsupported Windows check item")

    if item_id in {"W-01", "W-02", "W-03", "W-04"}:
        try:
            api = api or NativeWindowsReadOnlyApi()
            if item_id == "W-04":
                threshold = api.lockout_threshold()
                return CheckObservation(item_id, "PASS" if threshold <= 5 else "FAIL", "KISA_W04_THRESHOLD", {"lockout_threshold": threshold})
            accounts = api.accounts()
            if item_id == "W-01":
                admin = next((a for a in accounts if a["user_id"] == 500), None)
                if admin is None:
                    return CheckObservation(item_id, "UNABLE", "ADMINISTRATOR_ACCOUNT_NOT_FOUND", {})
                if admin["name"] != "Administrator":
                    return CheckObservation(item_id, "PASS", "KISA_W01_NAME_CHANGED", {"administrator_account_name": admin["name"]})
                return CheckObservation(item_id, "UNABLE", "PASSWORD_STRENGTH_NOT_READ", {"administrator_account_name": admin["name"]})
            if item_id == "W-02":
                guest = next((a for a in accounts if a["user_id"] == 501), None)
                if guest is None:
                    return CheckObservation(item_id, "UNABLE", "GUEST_ACCOUNT_NOT_FOUND", {})
                return CheckObservation(item_id, "PASS" if guest["disabled"] else "FAIL", "KISA_W02_GUEST_STATE", {"guest_disabled": guest["disabled"]})
            return CheckObservation(item_id, "UNABLE", "UNNECESSARY_ACCOUNT_REQUIRES_ADMINISTRATIVE_CONTEXT", {"account_count": len(accounts)})
        except (WindowsApiUnavailable, OSError) as exc:
            return CheckObservation(item_id, "UNABLE", "WINDOWS_API_UNAVAILABLE", {"error": str(exc)})

    if item_id == "W-05":
        return CheckObservation(item_id, "UNABLE", "LOCAL_SECURITY_POLICY_READ_NOT_IMPLEMENTED", {})

    # The requirements document does not define a W-27 baseline or comparison rule.
    # Keep the available read-only OS observation, but never infer PASS/FAIL.
    if item_id == "W-27":
        return CheckObservation(
            item_id=item_id,
            status="UNABLE",
            reason_code="CHECK_CRITERIA_NOT_DOCUMENTED",
            current_value={
                "platform": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            },
        )

    return CheckObservation(
        item_id=item_id,
        status="UNABLE",
        reason_code="CHECK_CRITERIA_NOT_DOCUMENTED",
        current_value={},
    )
