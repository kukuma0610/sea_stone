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


class _UserInfo3(ctypes.Structure):
    _fields_ = [
        ("name", wintypes.LPWSTR), ("password", wintypes.LPWSTR), ("password_age", wintypes.DWORD),
        ("priv", wintypes.DWORD), ("home_dir", wintypes.LPWSTR), ("comment", wintypes.LPWSTR),
        ("flags", wintypes.DWORD), ("script_path", wintypes.LPWSTR), ("auth_flags", wintypes.DWORD),
        ("full_name", wintypes.LPWSTR), ("user_comment", wintypes.LPWSTR),
        ("parms", wintypes.LPWSTR), ("workstations", wintypes.LPWSTR),
        ("last_logon", wintypes.DWORD), ("last_logoff", wintypes.DWORD), ("acct_expires", wintypes.DWORD),
        ("max_storage", wintypes.DWORD), ("units_per_week", wintypes.DWORD), ("logon_hours", ctypes.POINTER(wintypes.BYTE)),
        ("bad_pw_count", wintypes.DWORD), ("num_logons", wintypes.DWORD), ("logon_server", wintypes.LPWSTR),
        ("country_code", wintypes.DWORD), ("code_page", wintypes.DWORD), ("user_id", wintypes.DWORD),
        ("primary_group_id", wintypes.DWORD), ("profile", wintypes.LPWSTR), ("home_dir_drive", wintypes.LPWSTR),
        ("password_expired", wintypes.DWORD),
    ]


class _UserModalsInfo3(ctypes.Structure):
    _fields_ = [("lockout_duration", wintypes.DWORD), ("lockout_observation_window", wintypes.DWORD), ("lockout_threshold", wintypes.DWORD)]


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
                    None, 3, 0, ctypes.byref(buffer), wintypes.DWORD(-1),
                    ctypes.byref(entries_read), ctypes.byref(total_entries), ctypes.byref(resume),
                )
                if status not in (0, 234):
                    raise WindowsApiUnavailable(f"NetUserEnum failed: {status}")
                rows = ctypes.cast(buffer, ctypes.POINTER(_UserInfo3))
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
        return self._required_policy_dword(
            r"SYSTEM\CurrentControlSet\Control\Lsa", "EveryoneIncludesAnonymous", {0, 1}
        ) == 1

    def anonymous_sid_name_translation_enabled(self) -> bool:
        return self._security_policy_flag("LSAAnonymousNameLookup")

    def blank_password_use_restricted(self) -> bool:
        return self._required_policy_dword(
            r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse", {0, 1}
        ) == 1

    def local_logon_principals(self) -> list[str]:
        entries = _parse_target_user_right(self._export_security_policy("USER_RIGHTS"), "SeInteractiveLogonRight")
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
        return self._required_policy_dword(
            r"SOFTWARE\Policies\Microsoft\Cryptography", "ForceKeyProtection", {0, 1, 2}
        )

    @staticmethod
    def _required_policy_dword(path: str, name: str, allowed: set[int]) -> int:
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, path, 0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                value, kind = winreg.QueryValueEx(key, name)
        except FileNotFoundError as exc:
            raise WindowsApiUnavailable(f"{name} registry value absent; effective default not verified") from exc
        except OSError as exc:
            raise WindowsApiUnavailable(f"{name} registry read failed") from exc
        if kind != winreg.REG_DWORD or value not in allowed:
            raise WindowsApiUnavailable(f"{name} registry type or value unsupported")
        return value

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
        return self._required_policy_dword(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ShutdownWithoutLogon", {0, 1},
        ) == 1

    def remote_shutdown_principal_counts(self) -> dict[str, int]:
        entries = _parse_target_user_right(self._export_security_policy("USER_RIGHTS"), "SeRemoteShutdownPrivilege")
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

    def _export_security_policy(self, area: str = "SECURITYPOLICY") -> str:
        if area not in {"SECURITYPOLICY", "USER_RIGHTS"}:
            raise ValueError("unsupported security policy export area")
        with tempfile.TemporaryDirectory(prefix="os-guard-policy-") as temp_dir:
            export_path = Path(temp_dir) / "security-policy.inf"
            try:
                completed = subprocess.run(
                    [
                        "secedit.exe", "/export", "/cfg", str(export_path),
                        "/areas", area, "/quiet",
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


def _parse_target_user_right(policy_text: str, policy_name: str) -> list[str]:
    section = ""
    for raw_line in policy_text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().casefold()
        elif section == "privilege rights" and "=" in line:
            key, value = line.split("=", 1)
            if key.strip().casefold() == policy_name.casefold():
                return [entry.strip() for entry in value.split(",") if entry.strip()]
    raise WindowsApiUnavailable(f"{policy_name} was not present in exported Privilege Rights")


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
