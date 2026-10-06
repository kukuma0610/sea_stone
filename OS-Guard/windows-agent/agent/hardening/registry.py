"""SEMI_AUTO allowlist와 W-code별 고정 조치 정의."""

from __future__ import annotations

from types import MappingProxyType

from .actions import HardeningAction, RegistryValueAction
from .policy_actions import new_actions


_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_POLICIES_SYSTEM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# 현재 CHECK가 읽는 경로·자료형과 KISA 양호값이 모두 명확한 항목만 등록한다.
_ACTIONS: dict[str, HardeningAction] = {
    "W-07": RegistryValueAction("W-07", _LSA, "EveryoneIncludesAnonymous", 0, "DWORD"),
    "W-13": RegistryValueAction("W-13", _LSA, "LimitBlankPasswordUse", 1, "DWORD"),
    "W-15": RegistryValueAction(
        "W-15", r"SOFTWARE\Policies\Microsoft\Cryptography", "ForceKeyProtection", 2, "DWORD"
    ),
    "W-48": RegistryValueAction("W-48", _POLICIES_SYSTEM, "ShutdownWithoutLogon", 0, "DWORD"),
    "W-50": RegistryValueAction("W-50", _LSA, "CrashOnAuditFail", 0, "DWORD"),
    "W-52": RegistryValueAction("W-52", _WINLOGON, "AutoAdminLogon", "0", "SZ"),
    "W-53": RegistryValueAction("W-53", _WINLOGON, "AllocateDASD", "0", "SZ"),
    "W-59": RegistryValueAction("W-59", _LSA, "LmCompatibilityLevel", 3, "DWORD"),
}

_ACTIONS.update(new_actions())
ACTION_REGISTRY = MappingProxyType(_ACTIONS)
SEMI_AUTO_ALLOWLIST = frozenset(_ACTIONS)


def get_action(code: str) -> HardeningAction:
    try:
        return ACTION_REGISTRY[code]
    except KeyError as exc:
        raise ValueError(f"hardening action is not allowlisted: {code}") from exc
