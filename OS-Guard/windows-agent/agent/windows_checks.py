import ctypes
import json
import os
import platform
import re
import subprocess
import tempfile
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
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
    "W-06": {"page": 182, "good": "Administrators 구성원 1명 이하 또는 불필요한 관리자 없음", "bad": "불필요한 관리자 존재"},
    "W-07": {"page": 184, "good": "Everyone 사용 권한을 익명 사용자에게 적용: 사용 안 함", "bad": "해당 정책: 사용"},
    "W-08": {"page": 185, "good": "계정 잠금 기간과 잠금 수 초기화 기간 모두 60분 이상", "bad": "미설정 또는 60분 미만"},
    "W-09": {"page": 187, "good": "비밀번호 관리 정책 모두 적용", "bad": "비밀번호 관리 정책 일부 미적용"},
    "W-10": {"page": 189, "good": "마지막 사용자 이름 표시 안 함: 사용", "bad": "해당 정책: 사용 안 함"},
    "W-11": {"page": 191, "good": "로컬 로그온 허용에 Administrators와 IUSR_만 존재", "bad": "그 외 계정 또는 그룹 존재"},
    "W-12": {"page": 192, "good": "익명 SID/이름 변환 허용: 사용 안 함", "bad": "해당 정책: 사용"},
    "W-13": {"page": 193, "good": "빈 암호 사용 제한: 사용", "bad": "해당 정책: 사용 안 함"},
    "W-14": {"page": 194, "good": "별도 원격 접속 계정이 있고 불필요한 계정 없음", "bad": "별도 원격 접속 계정 없음"},
    "W-15": {"page": 196, "good": "개인 키 사용 시마다 암호 입력", "bad": "개인 키 사용 시마다 암호를 입력하지 않음"},
    "W-16": {"page": 197, "good": "일반 공유가 없거나 Everyone 권한 없음", "bad": "일반 공유에 Everyone 권한 있음"},
    "W-17": {"page": 198, "good": "AutoShareServer 0이며 기본 공유 없음", "bad": "AutoShareServer 1 또는 기본 공유 존재"},
    "W-18": {"page": 200, "good": "일반적으로 불필요한 서비스 중지", "bad": "일반적으로 불필요한 서비스 실행 중"},
    "W-19": {"page": 204, "good": "IIS 미사용 또는 필요에 의해 사용", "bad": "IIS 불필요 사용"},
    "W-20": {"page": 205, "good": "TCP/IP와 NetBIOS 바인딩 제거", "bad": "TCP/IP와 NetBIOS 바인딩 유지"},
    "W-21": {"page": 207, "good": "FTP 미사용 또는 Secure FTP 사용", "bad": "암호화되지 않은 FTP 사용"},
    "W-22": {"page": 208, "good": "FTP 홈 디렉터리에 Everyone 권한 없음", "bad": "Everyone 권한 있음"},
    "W-23": {"page": 210, "good": "공유 서비스 미사용 또는 익명 인증 비활성화", "bad": "공유 서비스 익명 인증 활성화"},
    "W-24": {"page": 212, "good": "특정 IP만 FTP 접속 허용", "bad": "특정 IP 접근 제어 미적용"},
    "W-25": {"page": 214, "good": "DNS 비활성화, 영역 전송 차단 또는 특정 서버 제한", "bad": "그 외 영역 전송 설정"},
    "W-26": {"page": 216, "good": "IIS 미사용, Windows 2008 이상, 패치 적용, MSADC/레지스트리 없음 중 하나", "bad": "양호 조건 없음"},
    "W-27": {"page": 217, "good": "최신 Build 설치 및 적용 절차·방법 수립", "bad": "최신 Build 미설치 또는 절차·방법 미수립"},
    "W-28": {"page": 218, "good": "RDP 미사용 또는 암호화 수준 중간 이상", "bad": "RDP 사용 및 암호화 수준 낮음"},
    "W-29": {"page": 220, "good": "SNMP 미사용 또는 Community String 설정", "bad": "불필요한 SNMP 사용"},
    "W-30": {"page": 221, "good": "SNMP 미사용 또는 Community String이 public/private 아님", "bad": "SNMP 사용 및 public/private 사용"},
    "W-31": {"page": 222, "good": "SNMP 미사용 또는 특정 호스트의 패킷만 수신", "bad": "모든 호스트의 SNMP 패킷 수신"},
    "W-32": {"page": 223, "good": "DNS 미사용 또는 동적 업데이트 없음", "bad": "DNS 사용 및 동적 업데이트 설정"},
    "W-33": {"page": 225, "good": "HTTP/FTP/SMTP 접속 시 배너 정보 미노출", "bad": "접속 시 배너 정보 노출"},
    "W-34": {"page": 228, "good": "Telnet 미구동 또는 NTLM 인증", "bad": "Telnet 구동 및 NTLM 외 인증"},
    "W-35": {"page": 229, "good": "시스템 DSN 데이터 소스를 현재 사용", "bad": "시스템 DSN 데이터 소스를 현재 미사용"},
    "W-36": {"page": 230, "good": "원격 제어 Timeout 30분 이하", "bad": "Timeout 미적용 또는 30분 초과"},
    "W-37": {"page": 232, "good": "예약 작업을 주기적으로 점검하고 불필요 작업 제거", "bad": "주기적 점검 미수행 또는 불필요 작업 미제거"},
    "W-38": {"page": 233, "good": "패치 절차 수립 및 주기적 확인·설치", "bad": "절차 미수립 또는 주기적 패치 미설치"},
    "W-39": {"page": 234, "good": "백신 엔진 최신 업데이트 또는 망 격리 환경의 절차·방법 수립", "bad": "최신 업데이트 또는 망 격리 절차·방법 미수립"},
    "W-40": {"page": 235, "good": "감사 정책 권고 기준 충족", "bad": "감사 정책 권고 기준 미충족"},
    "W-41": {"page": 237, "good": "NTP 및 시각 동기화 설정", "bad": "NTP 및 시각 동기화 미설정"},
    "W-42": {"page": 239, "good": "최대 로그 10,240KB 이상 및 90일 이후 덮어쓰기", "bad": "최대 로그 10,240KB 미만 또는 90일 이하 덮어쓰기"},
    "W-43": {"page": 240, "good": "로그 디렉터리에 Everyone 권한 없음", "bad": "로그 디렉터리에 Everyone 권한 있음"},
    "W-44": {"page": 241, "good": "Remote Registry Service 중지", "bad": "Remote Registry Service 사용 중"},
    "W-45": {"page": 242, "good": "바이러스 백신 프로그램 설치", "bad": "바이러스 백신 프로그램 미설치"},
    "W-46": {"page": 243, "good": "SAM 파일에 Administrators와 SYSTEM만 모든 권한", "bad": "그 외 계정·그룹 권한 존재"},
    "W-47": {"page": 244, "good": "화면 보호기 사용, 대기 10분 이하, 해제 암호 사용", "bad": "미설정, 암호 미사용 또는 대기 10분 초과"},
    "W-48": {"page": 246, "good": "로그온하지 않고 시스템 종료 허용 사용 안 함", "bad": "해당 정책 사용"},
    "W-49": {"page": 248, "good": "원격 강제 종료 권한에 Administrators만 존재", "bad": "그 외 계정·그룹 존재"},
    "W-50": {"page": 249, "good": "감사 로그 불가 시 즉시 종료 사용 안 함", "bad": "해당 정책 사용"},
    "W-51": {"page": 251, "good": "SAM 계정과 공유의 익명 열거 허용 안 함 사용", "bad": "해당 정책 사용 안 함"},
    "W-52": {"page": 253, "good": "AutoAdminLogon 값 없음 또는 0", "bad": "AutoAdminLogon 값 1"},
    "W-53": {"page": 254, "good": "이동식 미디어 포맷 및 꺼내기 허용 Administrators", "bad": "Administrators 외 허용"},
    "W-54": {"page": 255, "good": "4개 DoS 방어 레지스트리 기준값 설정", "bad": "DoS 방어 레지스트리 미설정"},
    "W-55": {"page": 256, "good": "사용자가 프린터 드라이버를 설치할 수 없게 함 사용", "bad": "해당 정책 사용 안 함"},
    "W-56": {"page": 257, "good": "로그온 시간 만료 시 연결 끊기 사용 및 SMB 유휴 시간 15분 이하", "bad": "연결 끊기 사용 안 함 또는 유휴 시간 15분 초과"},
    "W-57": {"page": 259, "good": "로그온 경고 메시지 제목과 내용 설정", "bad": "제목 또는 내용 미설정"},
    "W-58": {"page": 261, "good": "사용자 홈 디렉터리에 Everyone 권한 없음", "bad": "Everyone 권한 있음"},
    "W-59": {"page": 263, "good": "NTLMv2 응답만 전송", "bad": "LM 또는 NTLM 인증 설정"},
    "W-60": {"page": 265, "good": "보안 채널 암호화·서명 3개 정책 모두 사용", "bad": "3개 정책 중 일부 사용 안 함"},
    "W-61": {"page": 267, "good": "NTFS 파일 시스템 사용", "bad": "FAT 파일 시스템 사용"},
    "W-62": {"page": 268, "good": "시작 프로그램을 정기 검사하고 불필요 서비스 비활성화", "bad": "정기 미검사 및 불필요 서비스 실행"},
    "W-63": {"page": 269, "good": "컴퓨터 시계 동기화 최대 허용 오차 5분 이하", "bad": "최대 허용 오차 5분 초과"},
    "W-64": {"page": 270, "good": "Windows 방화벽 사용", "bad": "Windows 방화벽 사용 안 함"},
}


@dataclass(frozen=True)
class CheckObservation:
    item_id: str
    status: str
    reason_code: str
    current_value: dict[str, Any]
    observed_at: str = ""
    source_page: int | None = None
    manual_review_required: bool = False
    evidence_redacted: bool = True
    error_reason: str | None = None


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


class _UserModalsInfo0(ctypes.Structure):
    _fields_ = [
        ("min_password_length", wintypes.DWORD),
        ("max_password_age", wintypes.DWORD),
        ("min_password_age", wintypes.DWORD),
        ("force_logoff", wintypes.DWORD),
        ("password_history_length", wintypes.DWORD),
    ]


class _LocalGroupMembersInfo2(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("sid_usage", ctypes.c_int),
        ("domain_and_name", wintypes.LPWSTR),
    ]


class NativeWindowsReadOnlyApi:
    """Read-only Windows API adapter with a fixed security-policy export command."""

    def __init__(self):
        if os.name != "nt":
            raise WindowsApiUnavailable("Windows Server API is unavailable on this host")
        self._netapi = ctypes.WinDLL("Netapi32.dll")
        self._netapi.NetApiBufferFree.argtypes = [ctypes.c_void_p]
        self._netapi.NetApiBufferFree.restype = wintypes.DWORD
        self._netapi.NetUserEnum.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        self._netapi.NetUserEnum.restype = wintypes.DWORD
        self._netapi.NetUserModalsGet.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        self._netapi.NetUserModalsGet.restype = wintypes.DWORD
        self._netapi.NetLocalGroupGetMembers.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        self._netapi.NetLocalGroupGetMembers.restype = wintypes.DWORD
        self._netapi.NetGetJoinInformation.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(ctypes.c_int)]
        self._netapi.NetGetJoinInformation.restype = wintypes.DWORD

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
        return self.lockout_policy()["threshold"]

    def lockout_policy(self) -> dict[str, int]:
        buffer = ctypes.c_void_p()
        status = self._netapi.NetUserModalsGet(None, 3, ctypes.byref(buffer))
        if status != 0:
            raise WindowsApiUnavailable(f"NetUserModalsGet failed: {status}")
        try:
            policy = ctypes.cast(buffer, ctypes.POINTER(_UserModalsInfo3)).contents
            return {
                "threshold": policy.lockout_threshold,
                "reset_seconds": policy.lockout_observation_window,
                "duration_seconds": policy.lockout_duration,
            }
        finally:
            self._netapi.NetApiBufferFree(buffer)

    def password_policy(self) -> dict[str, int | bool]:
        buffer = ctypes.c_void_p()
        status = self._netapi.NetUserModalsGet(None, 0, ctypes.byref(buffer))
        if status != 0:
            raise WindowsApiUnavailable(f"NetUserModalsGet failed: {status}")
        try:
            policy = ctypes.cast(buffer, ctypes.POINTER(_UserModalsInfo0)).contents
            return {
                "minimum_length": policy.min_password_length,
                "maximum_age_seconds": policy.max_password_age,
                "minimum_age_seconds": policy.min_password_age,
                "history_length": policy.password_history_length,
                "complexity_enabled": self._security_policy_flag("PasswordComplexity"),
            }
        finally:
            self._netapi.NetApiBufferFree(buffer)

    def administrator_group_members(self) -> list[str]:
        return self._local_group_members("S-1-5-32-544")

    def remote_desktop_group_members(self) -> list[str]:
        return self._local_group_members("S-1-5-32-555")

    def _local_group_members(self, group_sid: str) -> list[str]:
        group_name = self._account_name_for_sid(group_sid).split("\\")[-1]
        buffer = ctypes.c_void_p()
        entries_read = wintypes.DWORD()
        total_entries = wintypes.DWORD()
        resume = wintypes.DWORD()
        members: list[str] = []
        try:
            while True:
                status = self._netapi.NetLocalGroupGetMembers(
                    None, group_name, 2, ctypes.byref(buffer), wintypes.DWORD(-1),
                    ctypes.byref(entries_read), ctypes.byref(total_entries), ctypes.byref(resume),
                )
                if status not in (0, 234):
                    raise WindowsApiUnavailable(f"NetLocalGroupGetMembers failed: {status}")
                rows = ctypes.cast(buffer, ctypes.POINTER(_LocalGroupMembersInfo2))
                members.extend((rows[i].domain_and_name or "") for i in range(entries_read.value))
                self._netapi.NetApiBufferFree(buffer)
                buffer = ctypes.c_void_p()
                if status != 234:
                    break
        finally:
            if buffer.value:
                self._netapi.NetApiBufferFree(buffer)
        return members

    def _account_name_for_sid(self, sid_string: str) -> str:
        advapi = ctypes.WinDLL("Advapi32.dll")
        kernel32 = ctypes.WinDLL("Kernel32.dll")
        advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
        advapi.LookupAccountSidW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int),
        ]
        advapi.LookupAccountSidW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        sid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW(sid_string, ctypes.byref(sid)):
            raise WindowsApiUnavailable("SID conversion failed")
        try:
            name_size = wintypes.DWORD(0)
            domain_size = wintypes.DWORD(0)
            sid_type = ctypes.c_int()
            advapi.LookupAccountSidW(None, sid, None, ctypes.byref(name_size), None, ctypes.byref(domain_size), ctypes.byref(sid_type))
            name = ctypes.create_unicode_buffer(name_size.value)
            domain = ctypes.create_unicode_buffer(domain_size.value)
            if not advapi.LookupAccountSidW(
                None, sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(sid_type)
            ):
                raise WindowsApiUnavailable("SID account lookup failed")
            return f"{domain.value}\\{name.value}" if domain.value else name.value
        finally:
            kernel32.LocalFree(sid.value)

    def domain_joined(self) -> bool:
        name_buffer = wintypes.LPWSTR()
        join_status = ctypes.c_int()
        status = self._netapi.NetGetJoinInformation(None, ctypes.byref(name_buffer), ctypes.byref(join_status))
        if status != 0:
            raise WindowsApiUnavailable(f"NetGetJoinInformation failed: {status}")
        try:
            return join_status.value == 3  # NetSetupDomainName
        finally:
            self._netapi.NetApiBufferFree(ctypes.cast(name_buffer, ctypes.c_void_p))

    def reversible_password_encryption_enabled(self) -> bool:
        return self._security_policy_flag("ClearTextPassword")

    def everyone_includes_anonymous(self) -> bool:
        return self._security_policy_flag("EveryoneIncludesAnonymous")

    def anonymous_sid_name_translation_enabled(self) -> bool:
        return self._security_policy_flag("LSAAnonymousNameLookup")

    def blank_password_use_restricted(self) -> bool:
        return self._security_policy_flag("LimitBlankPasswordUse")

    def local_logon_principals(self) -> list[str]:
        entries = _parse_security_policy_list(self._export_security_policy(), "SeInteractiveLogonRight")
        principals: list[str] = []
        for entry in entries:
            sid = entry.removeprefix("*")
            if sid == "S-1-5-32-544":
                principals.append("BUILTIN_ADMINISTRATORS")
            elif sid.startswith("S-"):
                principals.append(self._account_name_for_sid(sid))
            else:
                principals.append(entry)
        return principals

    def strong_key_protection_level(self) -> int:
        return _parse_registry_dword(
            self._export_security_policy(),
            r"MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection",
        )

    def shares(self) -> list[dict[str, Any]]:
        script = """
$everyone = (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([System.Security.Principal.NTAccount]).Value
$data = @(Get-SmbShare | ForEach-Object {
  $share = $_
  $hasEveryone = @($share | Get-SmbShareAccess -ErrorAction Stop | Where-Object { $_.AccountName -eq $everyone }).Count -gt 0
  [pscustomobject]@{ name = $share.Name; special = [bool]$share.Special; everyone_allowed = $hasEveryone }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def autoshare_server(self) -> int | None:
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\lanmanserver\parameters",
                0,
                winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "AutoShareServer")
                return int(value)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WindowsApiUnavailable("AutoShareServer registry read failed") from exc

    def running_services(self) -> list[dict[str, str]]:
        script = """
$data = @(Get-Service | Where-Object { $_.Status -eq 'Running' } | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; display_name = $_.DisplayName; status = [string]$_.Status }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def iis_services(self) -> list[dict[str, str]]:
        script = """
$data = @(Get-Service -Name W3SVC,IISADMIN -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; status = [string]$_.Status }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def netbios_bindings(self) -> list[dict[str, int]]:
        script = """
$data = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
  [pscustomobject]@{ interface_index = [int]$_.InterfaceIndex; tcpip_netbios_options = [int]$_.TcpipNetbiosOptions }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def ftp_inventory(self) -> dict[str, Any]:
        script = """
$service = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
$sites = @()
if (Get-Module -ListAvailable -Name WebAdministration) {
  Import-Module WebAdministration
  $sites = @(Get-Website | Where-Object { @($_.Bindings.Collection | ForEach-Object { $_.protocol }) -contains 'ftp' } | ForEach-Object {
    $site = $_
    $ssl = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.ftpServer/security/ssl' -Name '.'
    $anonymous = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -Name 'enabled'
    $authorization = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.ftpServer/security/authorization/add')
    $broadAuthorization = @($authorization | Where-Object { $_.accessType -eq 'Allow' -and ($_.users -eq '*' -or $_.roles -eq '*') }).Count -gt 0
    $everyoneAcl = $false
    $physicalPath = [Environment]::ExpandEnvironmentVariables([string]$site.PhysicalPath)
    if (Test-Path -LiteralPath $physicalPath) {
      $everyoneAcl = @((Get-Acl -LiteralPath $physicalPath).Access | Where-Object {
        try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' } catch { $false }
      }).Count -gt 0
    }
    $ipSecurity = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.ftpServer/security/ipSecurity' -Name '.'
    $ipEntries = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.ftpServer/security/ipSecurity/add')
    [pscustomobject]@{
      ssl_control_policy = [string]$ssl.controlChannelPolicy
      ssl_data_policy = [string]$ssl.dataChannelPolicy
      anonymous_enabled = [bool]$anonymous.Value
      broad_authorization = $broadAuthorization
      everyone_acl = $everyoneAcl
      ip_allow_unlisted = [bool]$ipSecurity.allowUnlisted
      ip_allow_count = @($ipEntries | Where-Object { $_.allowed -eq $true }).Count
    }
  })
}
$data = @([pscustomobject]@{
  service_installed = $null -ne $service
  service_running = $null -ne $service -and $service.Status -eq 'Running'
  sites = @($sites)
})
ConvertTo-Json -InputObject $data -Depth 5 -Compress
"""
        return self._run_powershell_json(script)[0]

    def auxiliary_share_services(self) -> list[dict[str, str]]:
        script = """
$data = @(Get-Service -Name NfsService,Tftpd,TFTP -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; status = [string]$_.Status }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def dns_inventory(self) -> dict[str, Any]:
        script = """
$service = Get-Service -Name DNS -ErrorAction SilentlyContinue
$zones = @()
if ($null -ne $service -and $service.Status -eq 'Running') {
  if (-not (Get-Module -ListAvailable -Name DnsServer)) { throw 'DnsServer module unavailable' }
  Import-Module DnsServer
  $zones = @(Get-DnsServerZone | Where-Object { [string]$_.ZoneType -eq 'Primary' } | ForEach-Object {
    [pscustomobject]@{
      transfer_type = [string]$_.SecureSecondaries
      secondary_server_count = @($_.SecondaryServers).Count
      dynamic_update = [string]$_.DynamicUpdate
    }
  })
}
$data = @([pscustomobject]@{
  service_installed = $null -ne $service
  service_running = $null -ne $service -and $service.Status -eq 'Running'
  zones = @($zones)
})
ConvertTo-Json -InputObject $data -Depth 4 -Compress
"""
        return self._run_powershell_json(script)[0]

    def windows_os_info(self) -> dict[str, str]:
        script = """
$os = Get-CimInstance Win32_OperatingSystem
$data = @([pscustomobject]@{ caption = [string]$os.Caption; version = [string]$os.Version; build_number = [string]$os.BuildNumber })
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def rdp_inventory(self) -> dict[str, Any]:
        import winreg

        running = self._service_running("TermService")
        encryption_level: int | None = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                0,
                winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MinEncryptionLevel")
                encryption_level = int(value)
        except FileNotFoundError:
            encryption_level = None
        except OSError as exc:
            raise WindowsApiUnavailable("RDP encryption level registry read failed") from exc
        return {"service_running": running, "minimum_encryption_level": encryption_level}

    def snmp_inventory(self) -> dict[str, Any]:
        import winreg

        running = self._service_running("SNMP")
        communities: list[str] = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities",
                0,
                winreg.KEY_READ,
            ) as key:
                index = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(key, index)
                        communities.append(name)
                        index += 1
                    except OSError:
                        break
        except FileNotFoundError:
            communities = []
        except OSError as exc:
            raise WindowsApiUnavailable("SNMP community registry read failed") from exc
        defaults = sum(name.casefold() in {"public", "private"} for name in communities)
        return {
            "service_running": running,
            "community_count": len(communities),
            "default_community_count": defaults,
        }

    def snmp_access_inventory(self) -> dict[str, Any]:
        import winreg

        running = self._service_running("SNMP")
        permitted_manager_count = 0
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers",
                0,
                winreg.KEY_READ,
            ) as key:
                while True:
                    try:
                        winreg.EnumValue(key, permitted_manager_count)
                        permitted_manager_count += 1
                    except OSError:
                        break
        except FileNotFoundError:
            permitted_manager_count = 0
        except OSError as exc:
            raise WindowsApiUnavailable("SNMP permitted managers registry read failed") from exc
        return {"service_running": running, "permitted_manager_count": permitted_manager_count}

    def banner_service_inventory(self) -> list[dict[str, str]]:
        script = """
$data = @(Get-Service -Name W3SVC,FTPSVC,SMTPSVC -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; status = [string]$_.Status }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def odbc_inventory(self) -> dict[str, int]:
        script = """
$dsns = @(Get-OdbcDsn -DsnType System -ErrorAction Stop)
$drivers = @(Get-OdbcDriver -ErrorAction Stop)
$data = @([pscustomobject]@{
  system_dsn_count = $dsns.Count
  driver_count = $drivers.Count
  system_dsn_names = @($dsns | ForEach-Object { [string]$_.Name })
  driver_names = @($drivers | ForEach-Object { [string]$_.Name })
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def remote_idle_timeout_minutes(self) -> int | None:
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                0,
                winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MaxIdleTime")
                return int(value) // 60000
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WindowsApiUnavailable("remote idle timeout registry read failed") from exc

    def scheduled_task_inventory(self) -> dict[str, int]:
        script = """
$tasks = @(Get-ScheduledTask -ErrorAction Stop)
$nonMicrosoft = @($tasks | Where-Object { -not $_.TaskPath.StartsWith('\\Microsoft\\') })
$data = @([pscustomobject]@{
  task_count = $tasks.Count
  non_microsoft_task_count = $nonMicrosoft.Count
  non_microsoft_task_identifiers = @($nonMicrosoft | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def patch_inventory(self) -> dict[str, Any]:
        script = """
$fixes = @(Get-HotFix -ErrorAction Stop)
$latest = $fixes | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$data = @([pscustomobject]@{
  installed_hotfix_count = $fixes.Count
  latest_installed_on = if ($null -ne $latest) { $latest.InstalledOn.ToString('yyyy-MM-dd') } else { $null }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def antivirus_inventory(self) -> dict[str, Any]:
        script = """
$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
$data = @([pscustomobject]@{
  defender_status_available = $null -ne $status
  antivirus_enabled = $null -ne $status -and [bool]$status.AntivirusEnabled
  signature_last_updated = if ($null -ne $status -and $null -ne $status.AntivirusSignatureLastUpdated) { $status.AntivirusSignatureLastUpdated.ToString('o') } else { $null }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def audit_policy(self) -> dict[str, int]:
        policy = self._export_security_policy()
        names = (
            "AuditAccountManage", "AuditAccountLogon", "AuditPrivilegeUse",
            "AuditDSAccess", "AuditLogonEvents", "AuditPolicyChange",
        )
        return {name: _parse_security_policy_number(policy, name) for name in names}

    def time_sync_inventory(self) -> dict[str, Any]:
        import winreg

        service_running = self._service_running("W32Time")
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
                0,
                winreg.KEY_READ,
            ) as key:
                sync_type, _ = winreg.QueryValueEx(key, "Type")
                try:
                    ntp_server, _ = winreg.QueryValueEx(key, "NtpServer")
                except FileNotFoundError:
                    ntp_server = ""
        except (FileNotFoundError, OSError) as exc:
            raise WindowsApiUnavailable("Windows time configuration read failed") from exc
        return {
            "service_running": service_running,
            "sync_type": str(sync_type),
            "ntp_server_configured": bool(str(ntp_server).strip()),
        }

    def event_log_inventory(self) -> list[dict[str, Any]]:
        script = """
$data = @('Application','Security','System' | ForEach-Object {
  $log = Get-WinEvent -ListLog $_ -ErrorAction Stop
  [pscustomobject]@{ name = $_; maximum_size_kb = [int64]($log.MaximumSizeInBytes / 1KB); log_mode = [string]$log.LogMode }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def log_directory_inventory(self) -> list[dict[str, Any]]:
        script = r"""
$everyoneSid = 'S-1-1-0'
$paths = @("$env:SystemRoot\System32\config", "$env:SystemRoot\System32\LogFiles")
$data = @($paths | ForEach-Object {
  $path = $_
  $present = Test-Path -LiteralPath $path
  $everyone = $false
  if ($present) {
    $everyone = @((Get-Acl -LiteralPath $path -ErrorAction Stop).Access | Where-Object {
      try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $everyoneSid } catch { $false }
    }).Count -gt 0
  }
  [pscustomobject]@{ present = $present; everyone_access = $everyone }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    def remote_registry_running(self) -> bool:
        return self._service_running("RemoteRegistry")

    def sam_acl_inventory(self) -> dict[str, int]:
        script = r"""
$path = "$env:SystemRoot\System32\config\SAM"
$allowed = @('S-1-5-18','S-1-5-32-544')
$rules = @((Get-Acl -LiteralPath $path -ErrorAction Stop).Access)
$unexpected = @($rules | Where-Object {
  try { $allowed -notcontains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $true }
})
$data = @([pscustomobject]@{ access_rule_count = $rules.Count; unexpected_principal_count = $unexpected.Count })
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def screen_saver_inventory(self) -> dict[str, Any]:
        import winreg

        values: dict[str, str | None] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_READ) as key:
                for name in ("ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut"):
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        values[name] = str(value)
                    except FileNotFoundError:
                        values[name] = None
        except OSError as exc:
            raise WindowsApiUnavailable("screen saver settings read failed") from exc
        timeout = int(values["ScreenSaveTimeOut"]) if values["ScreenSaveTimeOut"] and values["ScreenSaveTimeOut"].isdigit() else None
        return {
            "enabled": values["ScreenSaveActive"] == "1",
            "password_protected": values["ScreenSaverIsSecure"] == "1",
            "timeout_seconds": timeout,
        }

    def shutdown_without_logon(self) -> bool | None:
        return self._read_optional_registry_bool(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "ShutdownWithoutLogon"
        )

    def remote_shutdown_principal_counts(self) -> dict[str, int]:
        entries = _parse_security_policy_list(self._export_security_policy(), "SeRemoteShutdownPrivilege")
        normalized = [entry.removeprefix("*") for entry in entries]
        return {
            "principal_count": len(normalized),
            "unexpected_principal_count": sum(sid != "S-1-5-32-544" for sid in normalized),
        }

    def crash_on_audit_fail(self) -> bool | None:
        return self._read_optional_registry_bool(r"SYSTEM\CurrentControlSet\Control\Lsa", "CrashOnAuditFail")

    def anonymous_enumeration_restricted(self) -> dict[str, int | None]:
        path = r"SYSTEM\CurrentControlSet\Control\Lsa"
        return {
            "restrict_anonymous": self._read_optional_registry_int(path, "RestrictAnonymous"),
            "restrict_anonymous_sam": self._read_optional_registry_int(path, "RestrictAnonymousSAM"),
        }

    def auto_admin_logon(self) -> int:
        value = self._read_optional_registry_int(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon"
        )
        return 0 if value is None else value

    def removable_media_eject_policy(self) -> int | None:
        return self._read_optional_registry_int(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AllocateDASD"
        )

    def dos_defense_registry(self) -> dict[str, int | None]:
        path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        return {
            name: self._read_optional_registry_int(path, name)
            for name in ("SynAttackProtect", "EnableDeadGWDetect", "KeepAliveTime", "NoNameReleaseOnDemand")
        }

    def printer_driver_installation_prevented(self) -> bool | None:
        return self._read_optional_registry_bool(
            r"SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers",
            "AddPrinterDrivers",
        )

    def smb_session_policy(self) -> dict[str, int | None]:
        path = r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        return {
            "enable_forced_logoff": self._read_optional_registry_int(path, "EnableForcedLogOff"),
            "autodisconnect_minutes": self._read_optional_registry_int(path, "AutoDisconnect"),
        }

    def logon_warning_inventory(self) -> dict[str, bool]:
        import winreg

        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        values: dict[str, bool] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
                for name in ("legalnoticecaption", "legalnoticetext"):
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        values[name] = bool(str(value).strip())
                    except FileNotFoundError:
                        values[name] = False
        except FileNotFoundError:
            return {"caption_configured": False, "text_configured": False}
        except OSError as exc:
            raise WindowsApiUnavailable("logon warning registry read failed") from exc
        return {
            "caption_configured": values["legalnoticecaption"],
            "text_configured": values["legalnoticetext"],
        }

    def user_home_acl_inventory(self) -> dict[str, int]:
        script = r"""
$everyoneSid = 'S-1-1-0'
$profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and (Test-Path -LiteralPath $_.LocalPath) })
$exposed = @($profiles | Where-Object {
  $path = $_.LocalPath
  @((Get-Acl -LiteralPath $path -ErrorAction Stop).Access | Where-Object {
    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $everyoneSid } catch { $false }
  }).Count -gt 0
})
$data = @([pscustomobject]@{ profile_count = $profiles.Count; everyone_access_count = $exposed.Count })
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def lan_manager_authentication_level(self) -> int | None:
        return self._read_optional_registry_int(r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")

    def secure_channel_policy(self) -> dict[str, int | bool | None]:
        path = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        return {
            "domain_joined": self.domain_joined(),
            "require_sign_or_seal": self._read_optional_registry_int(path, "RequireSignOrSeal"),
            "seal_secure_channel": self._read_optional_registry_int(path, "SealSecureChannel"),
            "sign_secure_channel": self._read_optional_registry_int(path, "SignSecureChannel"),
        }

    def fixed_volume_inventory(self) -> dict[str, int]:
        script = """
$volumes = @(Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.FileSystem) })
$ntfs = @($volumes | Where-Object { $_.FileSystem -eq 'NTFS' }).Count
$fat = @($volumes | Where-Object { $_.FileSystem -in @('FAT','FAT32') }).Count
$other = $volumes.Count - $ntfs - $fat
$data = @([pscustomobject]@{ volume_count = $volumes.Count; ntfs_count = $ntfs; fat_count = $fat; other_filesystem_count = $other })
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def startup_inventory(self) -> dict[str, int]:
        script = """
$commands = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)
$automatic = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction Stop)
$data = @([pscustomobject]@{
  startup_command_count = $commands.Count
  automatic_service_count = $automatic.Count
  startup_identifiers = @($commands | ForEach-Object { [string]$_.Name })
  automatic_service_identifiers = @($automatic | ForEach-Object { [string]$_.Name })
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)[0]

    def kerberos_clock_skew_policy(self) -> dict[str, int | bool | None]:
        joined = self.domain_joined()
        if not joined:
            return {"domain_joined": False, "maximum_clock_skew_minutes": None}
        policy = self._export_security_policy()
        try:
            skew = _parse_security_policy_number(policy, "MaxClockSkew")
        except WindowsApiUnavailable:
            skew = self._read_optional_registry_int(
                r"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters", "MaxSkew"
            )
        return {"domain_joined": True, "maximum_clock_skew_minutes": skew}

    def firewall_profile_inventory(self) -> list[dict[str, Any]]:
        script = """
$data = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; enabled = [bool]$_.Enabled }
})
ConvertTo-Json -InputObject $data -Compress
"""
        return self._run_powershell_json(script)

    @staticmethod
    def _read_optional_registry_bool(path: str, value_name: str) -> bool | None:
        value = NativeWindowsReadOnlyApi._read_optional_registry_int(path, value_name)
        return None if value is None else value != 0

    @staticmethod
    def _read_optional_registry_int(path: str, value_name: str) -> int | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                return int(value)
        except FileNotFoundError:
            return None
        except (OSError, TypeError, ValueError) as exc:
            raise WindowsApiUnavailable(f"{value_name} registry read failed") from exc

    def _service_running(self, service_name: str) -> bool:
        if service_name not in {"TermService", "SNMP", "W32Time", "RemoteRegistry"}:
            raise WindowsApiUnavailable("service is not allowlisted")
        script = f"""
$service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
$data = @([pscustomobject]@{{ running = $null -ne $service -and $service.Status -eq 'Running' }})
ConvertTo-Json -InputObject $data -Compress
"""
        return bool(self._run_powershell_json(script)[0]["running"])

    def _run_powershell_json(self, script: str) -> list[dict[str, Any]]:
        script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); " + script
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                check=False,
                capture_output=True,
                timeout=30,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WindowsApiUnavailable("read-only PowerShell collection failed") from exc
        if completed.returncode != 0:
            raise WindowsApiUnavailable(f"read-only PowerShell collection failed: {completed.returncode}")
        try:
            value = json.loads(completed.stdout.decode("utf-8-sig")) if completed.stdout.strip() else []
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WindowsApiUnavailable("PowerShell JSON output was invalid") from exc
        return value if isinstance(value, list) else [value]

    def dont_display_last_username(self) -> bool:
        return _parse_dont_display_last_username(self._export_security_policy())

    def _security_policy_flag(self, policy_name: str) -> bool:
        return _parse_security_policy_flag(self._export_security_policy(), policy_name)

    def _export_security_policy(self) -> str:
        with tempfile.TemporaryDirectory(prefix="os-guard-policy-") as temp_dir:
            export_path = Path(temp_dir) / "security-policy.inf"
            try:
                completed = subprocess.run(
                    [
                        "secedit.exe", "/export", "/cfg", str(export_path),
                        "/areas", "SECURITYPOLICY", "/quiet",
                    ],
                    check=False,
                    capture_output=True,
                    timeout=20,
                    shell=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise WindowsApiUnavailable("security policy export failed") from exc
            if completed.returncode != 0 or not export_path.exists():
                raise WindowsApiUnavailable(f"security policy export failed: {completed.returncode}")
            raw = export_path.read_bytes()
            return _decode_security_policy(raw)


def _decode_security_policy(raw: bytes) -> str:
    for encoding in ("utf-16", "utf-8-sig", "cp949"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise WindowsApiUnavailable("security policy encoding is unsupported")


def _parse_reversible_password_encryption(policy_text: str) -> bool:
    return _parse_security_policy_flag(policy_text, "ClearTextPassword")


def _parse_security_policy_flag(policy_text: str, policy_name: str) -> bool:
    match = re.search(rf"(?mi)^\s*{re.escape(policy_name)}\s*=\s*([01])\s*$", policy_text)
    if not match:
        raise WindowsApiUnavailable(f"{policy_name} was not present in the exported policy")
    return match.group(1) == "1"


def _parse_security_policy_number(policy_text: str, policy_name: str) -> int:
    match = re.search(rf"(?mi)^\s*{re.escape(policy_name)}\s*=\s*(\d+)\s*$", policy_text)
    if not match:
        raise WindowsApiUnavailable(f"{policy_name} was not present in the exported policy")
    return int(match.group(1))


def _parse_dont_display_last_username(policy_text: str) -> bool:
    return _parse_registry_dword(
        policy_text,
        r"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName",
    ) == 1


def _parse_registry_dword(policy_text: str, registry_path: str) -> int:
    match = re.search(rf"(?mi)^{re.escape(registry_path)}\s*=\s*4\s*,\s*(\d+)\s*$", policy_text)
    if not match:
        raise WindowsApiUnavailable(f"{registry_path} was not present in the exported policy")
    return int(match.group(1))


def _parse_security_policy_list(policy_text: str, policy_name: str) -> list[str]:
    match = re.search(rf"(?mi)^\s*{re.escape(policy_name)}\s*=\s*(.*?)\s*$", policy_text)
    if not match:
        raise WindowsApiUnavailable(f"{policy_name} was not present in the exported policy")
    return [entry.strip() for entry in match.group(1).split(",") if entry.strip()]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _seconds_to_minutes(value: int) -> int:
    if value == 0xFFFFFFFF:
        return 0xFFFFFFFF
    return value // 60


def _seconds_to_days(value: int) -> int:
    if value == 0xFFFFFFFF:
        return 0xFFFFFFFF
    return value // 86400


def _mask_account_name(name: str) -> str:
    if len(name) <= 2:
        return "*" * len(name)
    return f"{name[0]}{'*' * (len(name) - 2)}{name[-1]}"


def _mask_identifier(value: str) -> str:
    return _mask_account_name(str(value))


def _result(
    item_id: str,
    status: str,
    reason_code: str,
    current_value: dict[str, Any],
    *,
    manual_review_required: bool = False,
    error_reason: str | None = None,
) -> CheckObservation:
    return CheckObservation(
        item_id=item_id,
        status=status,
        reason_code=reason_code,
        current_value=current_value,
        observed_at=_now(),
        source_page=KISA_SOURCES.get(item_id, {}).get("page"),
        manual_review_required=manual_review_required,
        evidence_redacted=True,
        error_reason=error_reason,
    )


def collect_check(item_id: str, api: Any | None = None) -> CheckObservation:
    if item_id not in WINDOWS_CHECKS:
        raise ValueError("unsupported Windows check item")

    if item_id in WINDOWS_CHECKS:
        try:
            api = api or NativeWindowsReadOnlyApi()
            if item_id == "W-04":
                threshold = api.lockout_threshold()
                return _result(item_id, "PASS" if threshold <= 5 else "FAIL", "KISA_W04_THRESHOLD", {"lockout_threshold": threshold})
            if item_id == "W-05":
                enabled = api.reversible_password_encryption_enabled()
                if api.domain_joined():
                    return _result(
                        item_id, "UNABLE", "DOMAIN_EFFECTIVE_POLICY_NOT_VERIFIED",
                        {"local_policy_enabled": enabled}, manual_review_required=True,
                        error_reason="Effective domain password policy requires VM verification",
                    )
                return _result(
                    item_id, "FAIL" if enabled else "PASS", "KISA_W05_REVERSIBLE_ENCRYPTION",
                    {"reversible_password_encryption_enabled": enabled},
                )
            if item_id == "W-06":
                members = api.administrator_group_members()
                evidence = [_mask_account_name(member) for member in members]
                if len(members) <= 1:
                    return _result(item_id, "PASS", "KISA_W06_ADMIN_COUNT", {"member_count": len(members), "members_masked": evidence})
                return _result(
                    item_id, "UNABLE", "UNNECESSARY_ADMIN_REQUIRES_MANUAL_REVIEW",
                    {"member_count": len(members), "members_masked": evidence}, manual_review_required=True,
                )
            if item_id == "W-07":
                enabled = api.everyone_includes_anonymous()
                return _result(item_id, "FAIL" if enabled else "PASS", "KISA_W07_ANONYMOUS_EVERYONE", {"everyone_includes_anonymous": enabled})
            if item_id == "W-08":
                policy = api.lockout_policy()
                duration = _seconds_to_minutes(policy["duration_seconds"])
                reset = _seconds_to_minutes(policy["reset_seconds"])
                passed = duration >= 60 and reset >= 60
                return _result(
                    item_id, "PASS" if passed else "FAIL", "KISA_W08_LOCKOUT_PERIODS",
                    {"lockout_duration_minutes": duration, "reset_lockout_count_minutes": reset},
                )
            if item_id == "W-09":
                policy = api.password_policy()
                values = {
                    "complexity_enabled": bool(policy["complexity_enabled"]),
                    "minimum_length": int(policy["minimum_length"]),
                    "maximum_age_days": _seconds_to_days(int(policy["maximum_age_seconds"])),
                    "minimum_age_days": _seconds_to_days(int(policy["minimum_age_seconds"])),
                    "history_length": int(policy["history_length"]),
                }
                passed = (
                    values["complexity_enabled"]
                    and values["minimum_length"] >= 8
                    and 0 < values["maximum_age_days"] <= 90
                    and values["minimum_age_days"] >= 1
                    and values["history_length"] >= 4
                )
                return _result(item_id, "PASS" if passed else "FAIL", "KISA_W09_PASSWORD_POLICY", values)
            if item_id == "W-10":
                enabled = api.dont_display_last_username()
                return _result(item_id, "PASS" if enabled else "FAIL", "KISA_W10_LAST_USERNAME", {"dont_display_last_username": enabled})
            if item_id == "W-11":
                principals = api.local_logon_principals()
                unexpected = [
                    principal for principal in principals
                    if principal != "BUILTIN_ADMINISTRATORS" and not principal.split("\\")[-1].startswith("IUSR_")
                ]
                evidence = [_mask_account_name(principal) for principal in principals]
                return _result(
                    item_id, "FAIL" if unexpected else "PASS", "KISA_W11_LOCAL_LOGON",
                    {"principal_count": len(principals), "principals_masked": evidence},
                )
            if item_id == "W-12":
                enabled = api.anonymous_sid_name_translation_enabled()
                return _result(item_id, "FAIL" if enabled else "PASS", "KISA_W12_ANONYMOUS_SID", {"anonymous_sid_name_translation_enabled": enabled})
            if item_id == "W-13":
                enabled = api.blank_password_use_restricted()
                return _result(item_id, "PASS" if enabled else "FAIL", "KISA_W13_BLANK_PASSWORD", {"blank_password_use_restricted": enabled})
            if item_id == "W-14":
                members = api.remote_desktop_group_members()
                evidence = [_mask_account_name(member) for member in members]
                if not members:
                    return _result(item_id, "FAIL", "KISA_W14_NO_DEDICATED_REMOTE_ACCOUNT", {"member_count": 0, "members_masked": []})
                return _result(
                    item_id, "UNABLE", "REMOTE_ACCOUNT_AUTHORIZATION_REQUIRES_MANUAL_REVIEW",
                    {"member_count": len(members), "members_masked": evidence}, manual_review_required=True,
                )
            if item_id == "W-15":
                level = api.strong_key_protection_level()
                return _result(item_id, "PASS" if level == 2 else "FAIL", "KISA_W15_STRONG_KEY_PROTECTION", {"strong_key_protection_level": level})
            if item_id == "W-16":
                normal_shares = [share for share in api.shares() if not bool(share["special"])]
                everyone_count = sum(bool(share["everyone_allowed"]) for share in normal_shares)
                return _result(
                    item_id, "FAIL" if everyone_count else "PASS", "KISA_W16_SHARE_EVERYONE",
                    {"normal_share_count": len(normal_shares), "everyone_share_count": everyone_count},
                )
            if item_id == "W-17":
                autoshare = api.autoshare_server()
                default_shares = [
                    share for share in api.shares()
                    if share["name"].upper() == "ADMIN$" or re.fullmatch(r"[A-Z]\$", share["name"].upper())
                ]
                passed = autoshare == 0 and not default_shares
                return _result(
                    item_id, "PASS" if passed else "FAIL", "KISA_W17_DEFAULT_SHARES",
                    {"autoshare_server": autoshare, "default_share_count": len(default_shares)},
                )
            if item_id == "W-18":
                services = api.running_services()
                evidence = [
                    {"service_name": service["name"], "status": service["status"]}
                    for service in services
                ]
                return _result(
                    item_id, "UNABLE", "SERVICE_NECESSITY_REQUIRES_MANUAL_REVIEW",
                    {"running_service_count": len(services), "running_services": evidence}, manual_review_required=True,
                )
            if item_id == "W-19":
                services = api.iis_services()
                running = [service for service in services if service["status"].lower() == "running"]
                if not running:
                    return _result(item_id, "PASS", "KISA_W19_IIS_NOT_RUNNING", {"installed_service_count": len(services), "running_service_count": 0})
                return _result(
                    item_id, "UNABLE", "IIS_NECESSITY_REQUIRES_MANUAL_REVIEW",
                    {"installed_service_count": len(services), "running_service_count": len(running)}, manual_review_required=True,
                )
            if item_id == "W-20":
                bindings = api.netbios_bindings()
                if not bindings:
                    return _result(item_id, "UNABLE", "IP_ENABLED_ADAPTER_NOT_FOUND", {}, manual_review_required=True)
                enabled_count = sum(binding["tcpip_netbios_options"] != 2 for binding in bindings)
                return _result(
                    item_id, "FAIL" if enabled_count else "PASS", "KISA_W20_NETBIOS_BINDING",
                    {"adapter_count": len(bindings), "not_disabled_count": enabled_count, "bindings": bindings},
                )
            if item_id in {"W-21", "W-22", "W-24"}:
                ftp = api.ftp_inventory()
                sites = ftp["sites"]
                if item_id == "W-21":
                    if not ftp["service_running"]:
                        return _result(item_id, "PASS", "KISA_W21_FTP_NOT_RUNNING", {"service_running": False, "site_count": len(sites)})
                    if not sites:
                        return _result(item_id, "UNABLE", "FTP_CONFIGURATION_NOT_FOUND", {"service_running": True}, manual_review_required=True)
                    insecure_count = sum(
                        site["ssl_control_policy"].lower() != "sslrequire" or site["ssl_data_policy"].lower() != "sslrequire"
                        for site in sites
                    )
                    return _result(
                        item_id, "FAIL" if insecure_count else "PASS", "KISA_W21_SECURE_FTP",
                        {"service_running": True, "site_count": len(sites), "insecure_site_count": insecure_count},
                    )
                if not sites:
                    return _result(item_id, "UNABLE", "FTP_SITE_NOT_CONFIGURED", {"site_count": 0}, manual_review_required=True)
                if item_id == "W-22":
                    exposed_count = sum(bool(site["everyone_acl"]) or bool(site["broad_authorization"]) for site in sites)
                    return _result(
                        item_id, "FAIL" if exposed_count else "PASS", "KISA_W22_FTP_PERMISSIONS",
                        {"site_count": len(sites), "everyone_or_broad_site_count": exposed_count},
                    )
                unrestricted_count = sum(bool(site["ip_allow_unlisted"]) or int(site["ip_allow_count"]) == 0 for site in sites)
                return _result(
                    item_id, "FAIL" if unrestricted_count else "PASS", "KISA_W24_FTP_IP_RESTRICTION",
                    {"site_count": len(sites), "unrestricted_site_count": unrestricted_count},
                )
            if item_id == "W-23":
                ftp = api.ftp_inventory()
                anonymous_count = sum(bool(site["anonymous_enabled"]) for site in ftp["sites"])
                if anonymous_count:
                    return _result(
                        item_id, "FAIL", "KISA_W23_FTP_ANONYMOUS_ENABLED",
                        {"ftp_site_count": len(ftp["sites"]), "anonymous_ftp_site_count": anonymous_count},
                    )
                normal_share_count = sum(not bool(share["special"]) for share in api.shares())
                auxiliary = api.auxiliary_share_services()
                if normal_share_count or auxiliary:
                    return _result(
                        item_id, "FAIL", "KISA_W23_SHARE_SERVICE_IN_USE",
                        {"ftp_site_count": len(ftp["sites"]), "normal_smb_share_count": normal_share_count, "auxiliary_share_service_count": len(auxiliary)},
                    )
                return _result(item_id, "PASS", "KISA_W23_ANONYMOUS_DISABLED", {"ftp_site_count": len(ftp["sites"]), "anonymous_ftp_site_count": 0})
            if item_id == "W-25":
                dns = api.dns_inventory()
                if not dns["service_running"]:
                    return _result(item_id, "PASS", "KISA_W25_DNS_NOT_RUNNING", {"service_running": False, "zone_count": 0})
                allowed = {"NoTransfer", "TransferToZoneNameServer", "TransferToSecureServers"}
                denied = {"TransferToAnyServer"}
                transfer_types = [zone["transfer_type"] for zone in dns["zones"]]
                if any(value not in allowed | denied for value in transfer_types):
                    return _result(
                        item_id, "UNABLE", "DNS_TRANSFER_TYPE_UNRECOGNIZED",
                        {"service_running": True, "zone_count": len(transfer_types)}, manual_review_required=True,
                    )
                insecure_count = sum(value in denied for value in transfer_types)
                return _result(
                    item_id, "FAIL" if insecure_count else "PASS", "KISA_W25_ZONE_TRANSFER",
                    {"service_running": True, "zone_count": len(transfer_types), "insecure_zone_count": insecure_count},
                )
            if item_id == "W-26":
                os_info = api.windows_os_info()
                if "Windows Server 2022" in os_info["caption"]:
                    return _result(item_id, "PASS", "KISA_W26_WINDOWS_2008_OR_LATER", {"caption": os_info["caption"], "build_number": os_info["build_number"]})
                return _result(
                    item_id, "UNABLE", "WINDOWS_VERSION_REQUIRES_MANUAL_REVIEW",
                    {"caption": os_info["caption"], "build_number": os_info["build_number"]}, manual_review_required=True,
                )
            if item_id == "W-27":
                os_info = api.windows_os_info()
                return _result(
                    item_id, "UNABLE", "LATEST_BUILD_AND_PROCEDURE_REQUIRE_MANUAL_REVIEW",
                    {"caption": os_info["caption"], "version": os_info["version"], "build_number": os_info["build_number"]},
                    manual_review_required=True,
                )
            if item_id == "W-28":
                rdp = api.rdp_inventory()
                if not rdp["service_running"]:
                    return _result(item_id, "PASS", "KISA_W28_RDP_NOT_RUNNING", {"service_running": False})
                level = rdp["minimum_encryption_level"]
                if level is None:
                    return _result(item_id, "UNABLE", "RDP_ENCRYPTION_LEVEL_NOT_FOUND", {"service_running": True}, manual_review_required=True)
                return _result(
                    item_id, "PASS" if level >= 2 else "FAIL", "KISA_W28_RDP_ENCRYPTION",
                    {"service_running": True, "minimum_encryption_level": level},
                )
            if item_id == "W-29":
                snmp = api.snmp_inventory()
                if not snmp["service_running"]:
                    return _result(item_id, "PASS", "KISA_W29_SNMP_NOT_RUNNING", {"service_running": False})
                status = "PASS" if snmp["community_count"] > 0 else "FAIL"
                return _result(
                    item_id, status, "KISA_W29_SNMP_COMMUNITY_CONFIGURED",
                    {"service_running": True, "community_count": snmp["community_count"]},
                )
            if item_id == "W-30":
                snmp = api.snmp_inventory()
                if not snmp["service_running"]:
                    return _result(item_id, "PASS", "KISA_W30_SNMP_NOT_RUNNING", {"service_running": False})
                if snmp["community_count"] == 0:
                    return _result(item_id, "UNABLE", "SNMP_COMMUNITY_NOT_FOUND", {"service_running": True}, manual_review_required=True)
                return _result(
                    item_id, "FAIL" if snmp["default_community_count"] else "PASS", "KISA_W30_COMMUNITY_COMPLEXITY",
                    {"service_running": True, "community_count": snmp["community_count"], "default_community_count": snmp["default_community_count"]},
                )
            if item_id == "W-31":
                snmp = api.snmp_access_inventory()
                if not snmp["service_running"]:
                    return _result(item_id, "PASS", "KISA_W31_SNMP_NOT_RUNNING", {"service_running": False})
                return _result(
                    item_id, "PASS" if snmp["permitted_manager_count"] else "FAIL", "KISA_W31_SNMP_ACCESS_CONTROL",
                    {"service_running": True, "permitted_manager_count": snmp["permitted_manager_count"]},
                )
            if item_id == "W-32":
                dns = api.dns_inventory()
                if not dns["service_running"]:
                    return _result(item_id, "PASS", "KISA_W32_DNS_NOT_RUNNING", {"service_running": False, "zone_count": 0})
                updates = [zone.get("dynamic_update") for zone in dns["zones"]]
                if not updates or any(value not in {"None", "Secure", "NonsecureAndSecure"} for value in updates):
                    return _result(
                        item_id, "UNABLE", "DNS_DYNAMIC_UPDATE_NOT_DETERMINED",
                        {"service_running": True, "zone_count": len(updates)}, manual_review_required=True,
                    )
                enabled_count = sum(value != "None" for value in updates)
                return _result(
                    item_id, "FAIL" if enabled_count else "PASS", "KISA_W32_DYNAMIC_UPDATE",
                    {"service_running": True, "zone_count": len(updates), "dynamic_update_zone_count": enabled_count},
                )
            if item_id == "W-33":
                services = api.banner_service_inventory()
                running = [service for service in services if service["status"].lower() == "running"]
                if not running:
                    return _result(item_id, "PASS", "KISA_W33_SERVICES_NOT_RUNNING", {"running_service_count": 0})
                return _result(
                    item_id, "UNABLE", "BANNER_EXPOSURE_REQUIRES_MANUAL_REVIEW",
                    {"running_service_count": len(running), "running_services": [service["name"] for service in running]},
                    manual_review_required=True,
                )
            if item_id == "W-34":
                os_info = api.windows_os_info()
                if "Windows Server 2022" in os_info["caption"]:
                    return _result(item_id, "NA", "KISA_W34_SERVER_2022_NOT_APPLICABLE", {"caption": os_info["caption"]})
                return _result(
                    item_id, "UNABLE", "TELNET_AUTHENTICATION_REQUIRES_APPLICABLE_OS_REVIEW",
                    {"caption": os_info["caption"]}, manual_review_required=True,
                )
            if item_id == "W-35":
                inventory = api.odbc_inventory()
                return _result(
                    item_id, "UNABLE", "ODBC_USAGE_REQUIRES_MANUAL_REVIEW",
                    {
                        "system_dsn_count": int(inventory["system_dsn_count"]),
                        "driver_count": int(inventory["driver_count"]),
                        "system_dsns_masked": [_mask_identifier(name) for name in inventory.get("system_dsn_names", [])],
                        "drivers_masked": [_mask_identifier(name) for name in inventory.get("driver_names", [])],
                    },
                    manual_review_required=True,
                )
            if item_id == "W-36":
                timeout = api.remote_idle_timeout_minutes()
                passed = timeout is not None and 0 < timeout <= 30
                return _result(
                    item_id, "PASS" if passed else "FAIL", "KISA_W36_REMOTE_IDLE_TIMEOUT",
                    {"idle_timeout_minutes": timeout},
                )
            if item_id == "W-37":
                inventory = api.scheduled_task_inventory()
                return _result(
                    item_id, "UNABLE", "SCHEDULED_TASK_NECESSITY_AND_REVIEW_CYCLE_REQUIRE_MANUAL_REVIEW",
                    {
                        "task_count": int(inventory["task_count"]),
                        "non_microsoft_task_count": int(inventory["non_microsoft_task_count"]),
                        "non_microsoft_tasks_masked": [_mask_identifier(name) for name in inventory.get("non_microsoft_task_identifiers", [])],
                    },
                    manual_review_required=True,
                )
            if item_id == "W-38":
                inventory = api.patch_inventory()
                return _result(
                    item_id, "UNABLE", "PATCH_PROCEDURE_AND_CURRENCY_REQUIRE_MANUAL_REVIEW",
                    {"installed_hotfix_count": int(inventory["installed_hotfix_count"]), "latest_installed_on": inventory["latest_installed_on"]},
                    manual_review_required=True,
                )
            if item_id == "W-39":
                inventory = api.antivirus_inventory()
                return _result(
                    item_id, "UNABLE", "ANTIVIRUS_CURRENCY_OR_ISOLATED_NETWORK_PROCEDURE_REQUIRES_MANUAL_REVIEW",
                    {
                        "defender_status_available": bool(inventory["defender_status_available"]),
                        "antivirus_enabled": bool(inventory["antivirus_enabled"]),
                        "signature_last_updated": inventory["signature_last_updated"],
                    },
                    manual_review_required=True,
                )
            if item_id == "W-40":
                policy = api.audit_policy()
                required = {
                    "AuditAccountManage": 2,
                    "AuditAccountLogon": 3,
                    "AuditPrivilegeUse": 3,
                    "AuditDSAccess": 2,
                    "AuditLogonEvents": 3,
                    "AuditPolicyChange": 3,
                }
                passed = all((int(policy[name]) & value) == value for name, value in required.items())
                return _result(item_id, "PASS" if passed else "FAIL", "KISA_W40_AUDIT_POLICY", {"audit_policy": policy})
            if item_id == "W-41":
                inventory = api.time_sync_inventory()
                sync_type = inventory["sync_type"].casefold()
                configured = (
                    bool(inventory["service_running"])
                    and sync_type not in {"", "nosync"}
                    and (sync_type == "nt5ds" or bool(inventory["ntp_server_configured"]))
                )
                return _result(item_id, "PASS" if configured else "FAIL", "KISA_W41_TIME_SYNC", inventory)
            if item_id == "W-42":
                logs = api.event_log_inventory()
                undersized_count = sum(int(log["maximum_size_kb"]) < 10240 for log in logs)
                evidence = {
                    "log_count": len(logs),
                    "undersized_log_count": undersized_count,
                    "logs": [{"name": log["name"], "maximum_size_kb": int(log["maximum_size_kb"]), "log_mode": log["log_mode"]} for log in logs],
                }
                if undersized_count:
                    return _result(item_id, "FAIL", "KISA_W42_LOG_SIZE", evidence)
                return _result(
                    item_id, "UNABLE", "EVENT_RETENTION_DAYS_NOT_AVAILABLE_ON_SERVER_2022",
                    evidence, manual_review_required=True,
                )
            if item_id == "W-43":
                directories = api.log_directory_inventory()
                if not directories or any(not bool(entry["present"]) for entry in directories):
                    return _result(
                        item_id, "UNABLE", "LOG_DIRECTORY_NOT_FOUND",
                        {"directory_count": len(directories)}, manual_review_required=True,
                    )
                everyone_count = sum(bool(entry["everyone_access"]) for entry in directories)
                return _result(
                    item_id, "FAIL" if everyone_count else "PASS", "KISA_W43_LOG_DIRECTORY_ACCESS",
                    {"directory_count": len(directories), "everyone_access_count": everyone_count},
                )
            if item_id == "W-44":
                running = api.remote_registry_running()
                return _result(item_id, "FAIL" if running else "PASS", "KISA_W44_REMOTE_REGISTRY", {"service_running": running})
            if item_id == "W-45":
                inventory = api.antivirus_inventory()
                if inventory["defender_status_available"]:
                    return _result(
                        item_id, "PASS", "KISA_W45_DEFENDER_INSTALLED",
                        {"defender_status_available": True, "antivirus_enabled": bool(inventory["antivirus_enabled"])},
                    )
                return _result(
                    item_id, "UNABLE", "THIRD_PARTY_ANTIVIRUS_REQUIRES_MANUAL_REVIEW",
                    {"defender_status_available": False}, manual_review_required=True,
                )
            if item_id == "W-46":
                inventory = api.sam_acl_inventory()
                return _result(
                    item_id, "FAIL" if inventory["unexpected_principal_count"] else "PASS", "KISA_W46_SAM_ACL",
                    {"access_rule_count": int(inventory["access_rule_count"]), "unexpected_principal_count": int(inventory["unexpected_principal_count"])},
                )
            if item_id == "W-47":
                inventory = api.screen_saver_inventory()
                return _result(
                    item_id, "UNABLE", "SCREEN_SAVER_IS_USER_SCOPED_REQUIRES_MANUAL_REVIEW",
                    inventory, manual_review_required=True,
                )
            if item_id == "W-48":
                enabled = api.shutdown_without_logon()
                if enabled is None:
                    return _result(item_id, "UNABLE", "SHUTDOWN_WITHOUT_LOGON_POLICY_NOT_FOUND", {}, manual_review_required=True)
                return _result(item_id, "FAIL" if enabled else "PASS", "KISA_W48_SHUTDOWN_WITHOUT_LOGON", {"enabled": enabled})
            if item_id == "W-49":
                inventory = api.remote_shutdown_principal_counts()
                passed = inventory["principal_count"] == 1 and inventory["unexpected_principal_count"] == 0
                return _result(item_id, "PASS" if passed else "FAIL", "KISA_W49_REMOTE_SHUTDOWN_RIGHT", inventory)
            if item_id == "W-50":
                enabled = api.crash_on_audit_fail()
                if enabled is None:
                    return _result(item_id, "UNABLE", "CRASH_ON_AUDIT_FAIL_POLICY_NOT_FOUND", {}, manual_review_required=True)
                return _result(item_id, "FAIL" if enabled else "PASS", "KISA_W50_CRASH_ON_AUDIT_FAIL", {"enabled": enabled})
            if item_id == "W-51":
                policy = api.anonymous_enumeration_restricted()
                if any(value is None for value in policy.values()):
                    return _result(item_id, "UNABLE", "ANONYMOUS_ENUMERATION_POLICY_NOT_FOUND", policy, manual_review_required=True)
                passed = policy["restrict_anonymous"] == 1 and policy["restrict_anonymous_sam"] == 1
                return _result(item_id, "PASS" if passed else "FAIL", "KISA_W51_ANONYMOUS_ENUMERATION", policy)
            if item_id == "W-52":
                value = api.auto_admin_logon()
                if value not in {0, 1}:
                    return _result(item_id, "UNABLE", "AUTO_ADMIN_LOGON_VALUE_UNRECOGNIZED", {"auto_admin_logon": value}, manual_review_required=True)
                return _result(item_id, "FAIL" if value == 1 else "PASS", "KISA_W52_AUTO_ADMIN_LOGON", {"auto_admin_logon": value})
            if item_id == "W-53":
                value = api.removable_media_eject_policy()
                if value is None:
                    return _result(item_id, "UNABLE", "REMOVABLE_MEDIA_POLICY_NOT_FOUND", {}, manual_review_required=True)
                return _result(item_id, "PASS" if value == 0 else "FAIL", "KISA_W53_REMOVABLE_MEDIA", {"policy_value": value})
            if item_id == "W-54":
                values = api.dos_defense_registry()
                if any(value is None for value in values.values()):
                    return _result(item_id, "FAIL", "KISA_W54_DOS_REGISTRY_NOT_CONFIGURED", values)
                passed = (
                    int(values["SynAttackProtect"]) >= 1
                    and values["EnableDeadGWDetect"] == 0
                    and values["KeepAliveTime"] == 300000
                    and values["NoNameReleaseOnDemand"] == 1
                )
                if passed:
                    return _result(item_id, "PASS", "KISA_W54_DOS_REGISTRY", values)
                return _result(item_id, "UNABLE", "DOS_REGISTRY_VALUES_OUTSIDE_DOCUMENTED_DECISION", values, manual_review_required=True)
            if item_id == "W-55":
                prevented = api.printer_driver_installation_prevented()
                if prevented is None:
                    return _result(item_id, "UNABLE", "PRINTER_DRIVER_POLICY_NOT_FOUND", {}, manual_review_required=True)
                return _result(item_id, "PASS" if prevented else "FAIL", "KISA_W55_PRINTER_DRIVER_INSTALL", {"prevented": prevented})
            if item_id == "W-56":
                policy = api.smb_session_policy()
                if any(value is None for value in policy.values()):
                    return _result(item_id, "UNABLE", "SMB_SESSION_POLICY_NOT_FOUND", policy, manual_review_required=True)
                passed = policy["enable_forced_logoff"] == 1 and int(policy["autodisconnect_minutes"]) <= 15
                return _result(item_id, "PASS" if passed else "FAIL", "KISA_W56_SMB_SESSION", policy)
            if item_id == "W-57":
                warning = api.logon_warning_inventory()
                passed = warning["caption_configured"] and warning["text_configured"]
                return _result(item_id, "PASS" if passed else "FAIL", "KISA_W57_LOGON_WARNING", warning)
            if item_id == "W-58":
                inventory = api.user_home_acl_inventory()
                return _result(
                    item_id, "FAIL" if inventory["everyone_access_count"] else "PASS", "KISA_W58_HOME_DIRECTORY_ACL",
                    {"profile_count": int(inventory["profile_count"]), "everyone_access_count": int(inventory["everyone_access_count"])},
                )
            if item_id == "W-59":
                level = api.lan_manager_authentication_level()
                if level is None or level not in range(0, 6):
                    return _result(item_id, "UNABLE", "LAN_MANAGER_LEVEL_NOT_DETERMINED", {"authentication_level": level}, manual_review_required=True)
                return _result(item_id, "PASS" if level >= 3 else "FAIL", "KISA_W59_LAN_MANAGER_LEVEL", {"authentication_level": level})
            if item_id == "W-60":
                policy = api.secure_channel_policy()
                if not policy["domain_joined"]:
                    return _result(item_id, "NA", "KISA_W60_NOT_DOMAIN_MEMBER", {"domain_joined": False})
                values = [policy["require_sign_or_seal"], policy["seal_secure_channel"], policy["sign_secure_channel"]]
                if any(value is None for value in values):
                    return _result(item_id, "UNABLE", "SECURE_CHANNEL_POLICY_NOT_FOUND", policy, manual_review_required=True)
                return _result(item_id, "PASS" if all(value == 1 for value in values) else "FAIL", "KISA_W60_SECURE_CHANNEL", policy)
            if item_id == "W-61":
                inventory = api.fixed_volume_inventory()
                if inventory["fat_count"]:
                    return _result(item_id, "FAIL", "KISA_W61_FAT_FILESYSTEM", inventory)
                if inventory["volume_count"] == 0 or inventory["other_filesystem_count"]:
                    return _result(item_id, "UNABLE", "FILESYSTEM_OUTSIDE_KISA_DECISION", inventory, manual_review_required=True)
                return _result(item_id, "PASS", "KISA_W61_NTFS_FILESYSTEM", inventory)
            if item_id == "W-62":
                inventory = api.startup_inventory()
                return _result(
                    item_id, "UNABLE", "STARTUP_NECESSITY_AND_REVIEW_CYCLE_REQUIRE_MANUAL_REVIEW",
                    {
                        "startup_command_count": int(inventory["startup_command_count"]),
                        "automatic_service_count": int(inventory["automatic_service_count"]),
                        "startup_items_masked": [_mask_identifier(name) for name in inventory.get("startup_identifiers", [])],
                        "automatic_services_masked": [_mask_identifier(name) for name in inventory.get("automatic_service_identifiers", [])],
                    },
                    manual_review_required=True,
                )
            if item_id == "W-63":
                policy = api.kerberos_clock_skew_policy()
                if not policy["domain_joined"]:
                    return _result(item_id, "UNABLE", "KERBEROS_POLICY_NOT_AVAILABLE_ON_NON_DOMAIN_MEMBER", {"domain_joined": False}, manual_review_required=True)
                skew = policy["maximum_clock_skew_minutes"]
                if skew is None:
                    return _result(item_id, "UNABLE", "KERBEROS_CLOCK_SKEW_POLICY_NOT_FOUND", policy, manual_review_required=True)
                return _result(item_id, "PASS" if int(skew) <= 5 else "FAIL", "KISA_W63_CLOCK_SKEW", policy)
            if item_id == "W-64":
                profiles = api.firewall_profile_inventory()
                if not profiles:
                    return _result(item_id, "UNABLE", "FIREWALL_PROFILES_NOT_FOUND", {}, manual_review_required=True)
                disabled_count = sum(not bool(profile["enabled"]) for profile in profiles)
                return _result(
                    item_id, "FAIL" if disabled_count else "PASS", "KISA_W64_FIREWALL",
                    {"profile_count": len(profiles), "disabled_profile_count": disabled_count, "profiles": profiles},
                )
            accounts = api.accounts()
            if item_id == "W-01":
                admin = next((a for a in accounts if a["user_id"] == 500), None)
                if admin is None:
                    return _result(item_id, "UNABLE", "ADMINISTRATOR_ACCOUNT_NOT_FOUND", {}, manual_review_required=True)
                if admin["name"] != "Administrator":
                    return _result(item_id, "PASS", "KISA_W01_NAME_CHANGED", {"administrator_name_changed": True})
                return _result(
                    item_id, "UNABLE", "PASSWORD_STRENGTH_REQUIRES_MANUAL_REVIEW",
                    {"administrator_name_changed": False}, manual_review_required=True,
                )
            if item_id == "W-02":
                guest = next((a for a in accounts if a["user_id"] == 501), None)
                if guest is None:
                    return _result(item_id, "UNABLE", "GUEST_ACCOUNT_NOT_FOUND", {}, manual_review_required=True)
                return _result(item_id, "PASS" if guest["disabled"] else "FAIL", "KISA_W02_GUEST_STATE", {"guest_disabled": guest["disabled"]})
            evidence = [
                {"account_name_masked": _mask_account_name(a["name"]), "disabled": bool(a["disabled"])}
                for a in accounts
            ]
            return _result(
                item_id, "UNABLE", "UNNECESSARY_ACCOUNT_REQUIRES_MANUAL_REVIEW",
                {"account_count": len(accounts), "accounts": evidence}, manual_review_required=True,
            )
        except (WindowsApiUnavailable, OSError, KeyError, TypeError, ValueError) as exc:
            return _result(
                item_id, "UNABLE", "WINDOWS_API_UNAVAILABLE", {},
                manual_review_required=True, error_reason=str(exc),
            )

    return _result(item_id, "UNABLE", "CHECK_CRITERIA_NOT_DOCUMENTED", {})
