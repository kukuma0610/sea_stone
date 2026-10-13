"""기존 읽기 전용 수집기를 사용한 CC-03 전체 관측 스냅샷."""

import socket
import platform
from ..checks.common import NativeWindowsReadOnlyApi


def collect_snapshot(manifest, agent_version, api=None):
    api = api or NativeWindowsReadOnlyApi()
    value = {"hostname": socket.gethostname(), "platform": "windows", "os": {"family": "WINDOWS"},
             "agent_version": agent_version, "module_version": manifest.version,
             "manifest_id": manifest.id, "roles": [], "services": [], "collection": {}}
    def failure(name):
        value["collection"][name] = {"status": "FAILED", "error":
            {"code": "COLLECTION_FAILED", "message": f"Windows {name} collection failed"}}
    try:
        os_info = api.windows_os_info()
        for key in ("caption", "version", "build_number"):
            if not isinstance(os_info.get(key), str) or not os_info[key]: raise ValueError()
        value["os"].update(distribution="Windows", edition=os_info["caption"], version=os_info["version"],
                            build=os_info["build_number"], architecture=platform.machine())
        value["collection"]["os"] = {"status": "SUCCEEDED", "error": None}
    except Exception:
        failure("os")
    try:
        # 업무 enum을 새로 정의하지 않고 Windows가 보고하는 설치 역할 이름을 사용한다.
        rows = api._run_powershell_json("""
$roles = @(Get-WindowsFeature -ErrorAction Stop | Where-Object {
  $_.Installed -and $_.FeatureType -eq 'Role'
} | ForEach-Object { [string]$_.Name })
$data = @([pscustomobject]@{ roles = @($roles) })
ConvertTo-Json -InputObject $data -Compress
""")
        roles = rows[0]["roles"]
        if not isinstance(roles, list) or not all(isinstance(role, str) and role for role in roles): raise ValueError()
        value["roles"] = roles
        value["collection"]["roles"] = {"status": "SUCCEEDED", "error": None}
    except Exception:
        failure("roles")
    try:
        services = api.running_services()
        value["services"] = [{"name": row["name"], "state": row["status"]} for row in services]
        value["collection"]["services"] = {"status": "SUCCEEDED", "error": None}
    except Exception:
        value["services"] = []
        failure("services")
    # 확장 스냅샷 hash는 Central에서 계산한다. 응답 version을 Heartbeat에 보존한다.
    return value
