"""승인된 등록 identity. CHECK 실행 manifest나 OS 지원 승인을 대신하지 않는다."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RegistrationRelease:
    version: str = "windows-2026.1"
    id: str = "manifest-windows-64-2026-v1"
    platform: str = "windows"
