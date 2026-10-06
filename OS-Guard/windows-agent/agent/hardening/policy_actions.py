"""고정 정책 키만 적용하는 신규 10개 조치와 전체 원복."""

from dataclasses import dataclass
from pathlib import Path
import ctypes
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from ..checks.common import NativeWindowsReadOnlyApi


class PolicySafetyError(RuntimeError):
    pass


class PolicyPreconditionError(PolicySafetyError):
    """쓰기 시작 전 거부: 새로 관측된 외부 변경을 원복하지 않는다."""


def system_executable(name):
    if name not in {"secedit.exe", "gpresult.exe"}:
        raise PolicySafetyError("executable is not allowlisted")
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer)):
        raise PolicySafetyError("system directory unavailable")
    return str(Path(buffer.value) / name)


def verify_local_gpo_files(system_directory):
    machine = Path(system_directory) / "GroupPolicy" / "Machine"
    # 원본 GPO를 함께 변경하지 않는 1차 구현에서는 별도 정책 재적용을 보수적으로 차단한다.
    registry = machine / "Registry.pol"
    try:
        raw = registry.read_bytes()
    except FileNotFoundError:
        raw = None
    if raw is not None and raw != b"PReg\x01\x00\x00\x00":
        raise PolicySafetyError("configured local registry GPO may override this action")
    template = machine / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf"
    try:
        template.read_bytes()
    except FileNotFoundError:
        return
    raise PolicySafetyError("configured local security GPO may override this action")


def run_fixed(args):
    completed = subprocess.run(
        args, shell=False, capture_output=True, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode:
        raise PolicySafetyError("fixed Windows policy operation failed")


def require_local_policy():
    api = NativeWindowsReadOnlyApi()
    info = api.windows_os_info()
    if "Windows Server 2022" not in info["caption"] or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise PolicySafetyError("64-bit Windows Server 2022 is required")
    if api.domain_joined():
        raise PolicySafetyError("domain-managed policy cannot be safely modified")
    verify_local_gpo_files(Path(system_executable("gpresult.exe")).parent)
    with tempfile.TemporaryDirectory(prefix="os-guard-rsop-") as temp:
        report = Path(temp) / "policy.xml"
        run_fixed([system_executable("gpresult.exe"), "/scope", "computer", "/x", str(report)])
        verify_rsop(report.read_bytes())


def verify_rsop(raw):
    root = ET.fromstring(raw)
    computers = [node for node in root.iter() if node.tag.split("}")[-1] == "ComputerResults"]
    if len(computers) != 1:
        raise PolicySafetyError("computer RSoP cannot be verified")
    gpos = [node for node in computers[0].iter() if node.tag.split("}")[-1] == "GPO"]
    if not gpos:
        raise PolicySafetyError("policy provenance is unavailable")
    for gpo in gpos:
        paths = [node.text for node in gpo if node.tag.split("}")[-1] == "Path"]
        if paths != ["LocalGPO"]:
            raise PolicySafetyError("non-local or unknown GPO is present")


@dataclass(frozen=True)
class Target:
    key: str
    section: str = "System Access"
    path: str = ""

    def identity(self):
        return {"name": self.key, "path": self.path or self.section}


class WindowsPolicyBackend:
    def verify(self):
        require_local_policy()

    @staticmethod
    def verify_native_value(target, value):
        # CHECK는 NetUserModalsGet의 초 단위 값을 읽는다. INF의 분/일 단위 표현이
        # 실제 값을 손실 없이 나타내는 경우에만 그 표현으로 저장·복원한다.
        lockout = {"LockoutDuration": ("duration_seconds", 60),
                   "ResetLockoutCount": ("reset_seconds", 60),
                   "LockoutBadCount": ("threshold", 1)}
        password = {"MinimumPasswordLength": ("minimum_length", 1),
                    "PasswordHistorySize": ("history_length", 1),
                    "MaximumPasswordAge": ("maximum_age_seconds", 86400),
                    "MinimumPasswordAge": ("minimum_age_seconds", 86400)}
        if target.key in lockout:
            field, multiplier = lockout[target.key]
            actual = NativeWindowsReadOnlyApi().lockout_policy()[field]
        elif target.key in password:
            field, multiplier = password[target.key]
            actual = NativeWindowsReadOnlyApi().password_policy()[field]
        else:
            return
        expected = 0xFFFFFFFF if value == -1 and multiplier != 1 else value * multiplier
        if actual != expected:
            raise PolicySafetyError("exported policy does not exactly represent current CHECK value")

    def read(self, target):
        if target.path:
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, target.path, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    value, kind = winreg.QueryValueEx(key, target.key)
            except FileNotFoundError:
                return {**target.identity(), "exists": False, "value": None, "type": None}
            if kind != winreg.REG_DWORD or type(value) is not int:
                raise PolicySafetyError("registry policy type is unsupported")
            return {**target.identity(), "exists": True, "value": value, "type": kind}
        area = "USER_RIGHTS" if target.section == "Privilege Rights" else "SECURITYPOLICY"
        text = NativeWindowsReadOnlyApi()._export_security_policy(area)
        section = ""
        found = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
            if section == target.section and "=" in line:
                key, value = line.split("=", 1)
                if key.strip() == target.key:
                    found.append(value.strip())
        if len(found) != 1:
            raise PolicySafetyError("policy value absent or ambiguous; rollback cannot be guaranteed")
        if target.section == "Privilege Rights":
            value = [sid.strip().removeprefix("*") for sid in found[0].split(",") if sid.strip()]
            if any(not re.fullmatch(r"S-1-\d+(?:-\d+)+", sid) for sid in value):
                raise PolicySafetyError("user right contains unresolved account identifiers")
            kind = "SID_LIST"
        else:
            value = int(found[0])
            kind = "POLICY_INTEGER"
            self.verify_native_value(target, value)
        return {**target.identity(), "exists": True, "value": value, "type": kind}

    def write(self, target, entry):
        if target.path:
            import winreg
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, target.path, 0,
                                    winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                if entry["exists"]:
                    winreg.SetValueEx(key, target.key, 0, entry["type"], entry["value"])
                else:
                    try:
                        winreg.DeleteValue(key, target.key)
                    except FileNotFoundError:
                        pass
            return
        if not entry["exists"]:
            raise PolicySafetyError("absence of security policy cannot be restored")
        if target.section == "Privilege Rights":
            value = ",".join("*" + sid for sid in entry["value"])
            area = "USER_RIGHTS"
        else:
            value = str(entry["value"])
            area = "SECURITYPOLICY"
        # 키/섹션은 고정 Target이며 값은 검증된 정수/SID 목록만 직렬화한다.
        template = ('[Unicode]\nUnicode=yes\n[Version]\nsignature="$CHICAGO$"\nRevision=1\n'
                    f'[{target.section}]\n{target.key} = {value}\n')
        with tempfile.TemporaryDirectory(prefix="os-guard-apply-") as temp:
            folder = Path(temp)
            cfg = folder / "policy.inf"
            cfg.write_text(template, encoding="utf-16")
            run_fixed([system_executable("secedit.exe"), "/configure", "/db", str(folder / "policy.sdb"),
                       "/cfg", str(cfg), "/overwrite", "/areas", area,
                       "/log", str(folder / "policy.log"), "/quiet"])


class PolicyTransactionAction:
    path = "LOCAL_POLICY_TRANSACTION"

    def __init__(self, code, targets, transform, backend=None):
        self.code = code
        self.name = code
        self.targets = tuple(targets)
        self.transform = transform
        self.backend = backend or WindowsPolicyBackend()

    def preflight(self):
        try:
            self.backend.verify()
        except Exception as exc:
            raise PolicyPreconditionError("local policy safety cannot be verified") from exc

    def capture(self):
        return {"targets": [self.backend.read(target) for target in self.targets]}

    def validate(self, entries):
        if not isinstance(entries, list) or len(entries) != len(self.targets):
            raise PolicySafetyError("snapshot targets do not match allowlist")
        for target, entry in zip(self.targets, entries):
            if set(entry) != {"name", "path", "exists", "value", "type"} or any(
                entry[key] != value for key, value in target.identity().items()
            ) or type(entry["exists"]) is not bool:
                raise PolicySafetyError("snapshot target is invalid")
            if not entry["exists"]:
                if not target.path or entry["value"] is not None or entry["type"] is not None:
                    raise PolicySafetyError("snapshot absence is invalid")
            elif target.section == "Privilege Rights" and not target.path:
                if entry["type"] != "SID_LIST" or not isinstance(entry["value"], list) or any(
                    not isinstance(sid, str) or not re.fullmatch(r"S-1-\d+(?:-\d+)+", sid)
                    for sid in entry["value"]
                ):
                    raise PolicySafetyError("snapshot SID list is invalid")
            elif type(entry["value"]) is not int or entry["type"] != (4 if target.path else "POLICY_INTEGER"):
                raise PolicySafetyError("snapshot policy type is invalid")

    def apply(self, before=None):
        self.preflight()
        try:
            entries = self.capture()["targets"]
            if before is not None and entries != before["targets"]:
                raise PolicySafetyError("policy changed since Before snapshot")
            self.validate(entries)
            values = self.transform([entry["value"] for entry in entries])
            if len(values) != len(entries):
                raise PolicySafetyError("transaction target count is invalid")
            updates = [{**entry, "exists": True, "value": value,
                        "type": 4 if target.path else entry["type"]}
                       for target, entry, value in zip(self.targets, entries, values)]
            self.validate(updates)
        except Exception as exc:
            raise PolicyPreconditionError("policy preparation failed before any write") from exc
        for target, entry, updated in zip(self.targets, entries, updates):
            if updated != entry:
                self.backend.write(target, updated)

    def restore(self, snapshot):
        entries = snapshot["targets"]
        self.validate(entries)
        errors = []
        # 한 값의 원복에 실패해도 나머지 모든 값에 대해 원복을 시도한다.
        for target, entry in reversed(list(zip(self.targets, entries))):
            try:
                self.backend.write(target, entry)
            except Exception:
                errors.append(target.key)
        if errors:
            raise PolicySafetyError("rollback failed for: " + ",".join(errors))
        if self.capture()["targets"] != entries:
            raise PolicySafetyError("rollback verification failed")


def lockout_threshold(values):
    return [values[0], values[1], min(values[2], 5)]


def lockout_periods(values):
    duration, reset, threshold = values
    reset = max(reset, 60)
    duration = -1 if duration == -1 else max(duration, reset, 60)
    return [duration, reset, threshold]


def password_policy(values):
    complexity, length, history, maximum, minimum = values
    maximum = 90 if maximum <= 0 else min(maximum, 90)
    minimum = max(minimum, 1)
    if minimum >= maximum:
        raise PolicySafetyError("password age constraints require manual review")
    return [1, max(length, 8), max(history, 4), maximum, minimum]


def idle_timeout(values):
    value = values[0]
    if value is not None and 0 < value < 60000:
        raise PolicySafetyError("sub-minute timeout cannot be weakened to satisfy current CHECK")
    if value is not None and value < 0:
        raise PolicySafetyError("invalid idle timeout")
    return [min(value, 1800000) if value else 1800000]


def new_actions():
    lockout = (Target("LockoutDuration"), Target("ResetLockoutCount"), Target("LockoutBadCount"))
    def registry(code, path, key, transform):
        return PolicyTransactionAction(code, (Target(key, path=path),), transform)
    return {
        "W-04": PolicyTransactionAction("W-04", lockout, lockout_threshold),
        "W-05": PolicyTransactionAction("W-05", (Target("ClearTextPassword"),), lambda v: [0]),
        "W-08": PolicyTransactionAction("W-08", lockout, lockout_periods),
        "W-09": PolicyTransactionAction("W-09", tuple(Target(key) for key in (
            "PasswordComplexity", "MinimumPasswordLength", "PasswordHistorySize",
            "MaximumPasswordAge", "MinimumPasswordAge")), password_policy),
        "W-10": registry("W-10", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                         "DontDisplayLastUserName", lambda v: [1]),
        "W-12": PolicyTransactionAction("W-12", (Target("LSAAnonymousNameLookup"),), lambda v: [0]),
        "W-28": registry("W-28", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                         "MinEncryptionLevel", lambda v: [max(v[0] or 0, 2)]),
        "W-36": registry("W-36", r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                         "MaxIdleTime", idle_timeout),
        "W-49": PolicyTransactionAction("W-49", (Target("SeRemoteShutdownPrivilege", "Privilege Rights"),),
                                        lambda v: [["S-1-5-32-544"]]),
        "W-55": registry("W-55", r"SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers",
                         "AddPrinterDrivers", lambda v: [1]),
    }
