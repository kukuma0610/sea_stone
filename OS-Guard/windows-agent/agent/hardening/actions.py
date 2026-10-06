"""고정된 Windows 레지스트리 조치만 제공하는 typed action."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class HardeningAction(Protocol):
    code: str
    path: str
    name: str

    def capture(self) -> dict[str, Any]: ...

    def apply(self) -> None: ...

    def restore(self, snapshot: dict[str, Any]) -> None: ...


@dataclass(frozen=True)
class RegistryValueAction:
    """생성 시 고정된 HKLM 값 하나만 읽고 쓰며 명령 문자열은 실행하지 않는다."""

    code: str
    path: str
    name: str
    target_value: int | str
    value_type: str

    def capture(self) -> dict[str, Any]:
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self.path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                value, kind = winreg.QueryValueEx(key, self.name)
                return {"exists": True, "value": value, "registry_type": kind}
        except FileNotFoundError:
            return {"exists": False, "value": None, "registry_type": None}

    def apply(self) -> None:
        import winreg

        kinds = {"DWORD": winreg.REG_DWORD, "SZ": winreg.REG_SZ}
        kind = kinds[self.value_type]
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            self.path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        ) as key:
            winreg.SetValueEx(key, self.name, 0, kind, self.target_value)

    def restore(self, snapshot: dict[str, Any]) -> None:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            self.path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        ) as key:
            if snapshot["existed"]:
                winreg.SetValueEx(
                    key, self.name, 0,
                    int(snapshot["value_type"]), snapshot["previous_value"],
                )
            else:
                try:
                    winreg.DeleteValue(key, self.name)
                except FileNotFoundError:
                    pass
