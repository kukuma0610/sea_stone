"""E2E 진단 전용. 이벤트 관측 성공은 History 예외 승인 근거로 사용하지 않는다."""

from datetime import datetime
from uuid import UUID
import xml.etree.ElementTree as ET

from agent.checks.common import NativeWindowsReadOnlyApi

CHANNEL = "Microsoft-Windows-GroupPolicy/Operational"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
STARTS = {4000: 8000, 4002: 8002, 4004: 8004, 4006: 8006}


class LiveDiagnosticError(ValueError):
    def __init__(self, reason):
        self.reason_code = reason
        self.location = "LIVE_GPO_SESSION"
        super().__init__(reason)


def fail(reason):
    raise LiveDiagnosticError(reason)


def date(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        fail("GPO_TIMESTAMP_INVALID")
    return result


def safe_xml(value):
    if not isinstance(value, str) or len(value) > 262144:
        fail("GPO_XML_INVALID")
    if "<!" in value:
        fail("GPO_XML_DECLARATION_FORBIDDEN")
    return ET.fromstring(value)


def machine(row):
    value = row["data"].get("IsMachine")
    if row["version"] == 1:
        if value not in {"0", "1"}:
            fail("GPO_MACHINE_FIELD_INVALID")
        return value == "1"
    if row["version"] == 0 and value in {"true", "false", "1", "0"}:
        return value in {"true", "1"}
    fail("GPO_EVENT_VERSION_UNSUPPORTED")


def validate(snapshot):
    """라이브 수집 결과 검증. RecordID 간격을 로그 삭제로 해석하지 않는다."""
    try:
        return _validate(snapshot)
    except LiveDiagnosticError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, ET.ParseError):
        fail("GPO_SNAPSHOT_INVALID")


def _validate(snapshot):
    boot, observed = date(snapshot["boot_time"]), date(snapshot["observed_at"])
    if boot > observed or snapshot["log_enabled"] is not True:
        fail("GPO_LOG_UNAVAILABLE")
    if snapshot["clear_check_verified"] is not True or snapshot["clear_count"] != 0:
        fail("GPO_LOG_CLEAR_OR_UNVERIFIED")
    if snapshot["truncated"] is not False:
        fail("GPO_LOG_TRUNCATED")
    if snapshot["before_record"] != snapshot["after_record"]:
        fail("GPO_LOG_CHANGED_DURING_QUERY")
    source = snapshot["events"]
    if not isinstance(source, list) or not source:
        fail("GPO_EVENTS_MISSING")
    rows = []
    for raw in source:
        node = safe_xml(raw)
        system = node.find("e:System", NS)
        provider = system.find("e:Provider", NS)
        if (provider.get("Name") != "Microsoft-Windows-GroupPolicy"
                or provider.get("Guid", "").lower() != "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}"
                or system.findtext("e:Channel", namespaces=NS) != CHANNEL):
            fail("GPO_PROVIDER_MISMATCH")
        data = {}
        for field in node.findall("e:EventData/e:Data", NS):
            name = field.get("Name")
            if not name or name in data:
                fail("GPO_DUPLICATE_FIELD")
            data[name] = field.text or ""
        row = {"id": int(system.findtext("e:EventID", namespaces=NS)),
               "version": int(system.findtext("e:Version", namespaces=NS)),
               "record": int(system.findtext("e:EventRecordID", namespaces=NS)),
               "time": date(system.find("e:TimeCreated", NS).get("SystemTime")),
               "level": int(system.findtext("e:Level", namespaces=NS)), "data": data}
        row["activity"] = str(UUID(system.find("e:Correlation", NS).get("ActivityID").strip("{}")))
        if not boot <= row["time"] <= observed:
            fail("GPO_EVENT_OUTSIDE_CURRENT_BOOT")
        if row["level"] not in {0, 4, 5}:
            fail("GPO_WARNING_OR_ERROR")
        if "ErrorCode" in data and int(data["ErrorCode"], 0) != 0:
            fail("GPO_SESSION_FAILED")
        if row["id"] in {5117, 5126, 5312, 5313} and row["version"] != 0:
            fail("GPO_EVENT_VERSION_UNSUPPORTED")
        rows.append(row)
    rows.sort(key=lambda row: row["record"])
    if len({r["record"] for r in rows}) != len(rows) or any(a["time"] > b["time"] for a, b in zip(rows, rows[1:])):
        fail("GPO_EVENT_ORDER_INVALID")
    if rows[-1]["record"] != snapshot["after_record"]:
        fail("GPO_QUERY_INCOMPLETE")
    starts = [r for r in rows if r["id"] in STARTS and machine(r)]
    if not starts or not any(r["id"] == 4000 for r in starts):
        fail("GPO_CURRENT_BOOT_START_MISSING")
    if len({r["activity"] for r in starts}) != len(starts):
        fail("GPO_SESSION_START_DUPLICATE")
    activities = {r["activity"] for r in starts}
    for row in rows:
        if row["id"] in {*STARTS.values(), 5117, 5126} and machine(row) and row["activity"] not in activities:
            fail("GPO_ORPHAN_MACHINE_EVENT")
    # 모든 컴퓨터 시작 세션의 완료를 먼저 검사한다. 최신 정상 세션만 골라 실패를 숨기지 않는다.
    for start in starts:
        group = [r for r in rows if r["activity"] == start["activity"]]
        end = [r for r in group if r["id"] == STARTS[start["id"]]]
        final = [r for r in group if r["id"] == 5117]
        if len(end) != 1 or len(final) != 1:
            fail("GPO_MACHINE_SESSION_INCOMPLETE")
        if not start["record"] < end[0]["record"] < final[0]["record"] or final[0] != group[-1]:
            fail("GPO_SESSION_ORDER_INVALID")
        if not machine(end[0]) or not machine(final[0]) or int(end[0]["data"]["ErrorCode"], 0) != 0:
            fail("GPO_SESSION_FAILED")
        if start["data"]["IsDomainJoined"] != "false" or end[0]["data"]["IsConnectivityFailure"] != "false":
            fail("GPO_DOMAIN_OR_CONNECTIVITY_FAILURE")
        if str(UUID(start["data"]["PolicyActivityId"].strip("{}"))) != start["activity"]:
            fail("GPO_ACTIVITY_MISMATCH")
    latest = starts[-1]
    group = [r for r in rows if r["activity"] == latest["activity"]]
    expected = [latest["id"], 5126, 5312, 5313, STARTS[latest["id"]], 5117]
    selected = []
    for event_id in expected:
        matches = [r for r in group if r["id"] == event_id]
        if len(matches) != 1:
            fail("GPO_REQUIRED_EVENT_MISSING_OR_DUPLICATE")
        selected.append(matches[0])
    if selected != sorted(selected, key=lambda row: row["record"]):
        fail("GPO_REQUIRED_EVENT_ORDER_INVALID")
    count, applied, excluded = selected[1:4]
    if any(row["version"] != 0 for row in (count, applied, excluded, selected[-1])):
        fail("GPO_EVENT_VERSION_UNSUPPORTED")
    if not machine(count) or any(int(count["data"][key]) != 0 for key in ("NumberOfGPOsDownloaded", "NumberOfGPOsApplicable")):
        fail("GPO_APPLIED_POLICY_FOUND")
    if applied["data"]["GPOInfoList"].strip():
        fail("GPO_APPLIED_POLICY_FOUND")
    gpo = safe_xml(excluded["data"]["GPOInfoList"])
    # 번역된 Name/DescriptionString은 판단에 사용하지 않는다.
    if (gpo.tag != "GPO" or gpo.findtext("SOM") != "Local" or gpo.findtext("Version") != "0"
            or gpo.findtext("Reason") != "NOTAPPLIED-EMPTY" or gpo.findall(".//GPO")
            or any(len(gpo.findall(key)) != 1 for key in ("SOM", "Version", "Reason"))):
        fail("GPO_LOCAL_POLICY_NOT_EMPTY")
    return {"boot_time": snapshot["boot_time"], "session_count": len(starts),
            "activity_id": latest["activity"], "start_record": latest["record"],
            "end_record": selected[-1]["record"], "applied_gpo_count": 0}


def collect():
    # 고정 읽기 전용 조회. 설정 변경, 로그 활성화, gpupdate, 파일 입력은 없다.
    query = r"""
$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-GroupPolicy/Operational'
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$log = Get-WinEvent -ListLog $channel
$before = Get-WinEvent -LogName $channel -MaxEvents 1
$events = @(Get-WinEvent -FilterHashtable @{LogName=$channel; StartTime=$boot} -MaxEvents 10001)
$clears = @()
try {
  $clears = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Eventlog'; Id=104; StartTime=$boot})
} catch {
  if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
$after = Get-WinEvent -LogName $channel -MaxEvents 1
$osAfter = Get-CimInstance Win32_OperatingSystem
if ($osAfter.LastBootUpTime -ne $boot) { throw 'BOOT_CHANGED' }
$data = @([pscustomobject]@{
  boot_time=$boot.ToUniversalTime().ToString('o'); observed_at=[DateTime]::UtcNow.ToString('o')
  log_enabled=[bool]$log.IsEnabled; clear_check_verified=$true; clear_count=$clears.Count
  truncated=($events.Count -ge 10001); before_record=[long]$before.RecordId; after_record=[long]$after.RecordId
  events=@($events | ForEach-Object { $_.ToXml() })
})
ConvertTo-Json -InputObject $data -Depth 5 -Compress
"""
    try:
        rows = NativeWindowsReadOnlyApi()._run_powershell_json(query)
        if len(rows) != 1:
            fail("GPO_LIVE_QUERY_INVALID")
        return validate(rows[0])
    except LiveDiagnosticError:
        raise
    except Exception:
        fail("GPO_LIVE_QUERY_FAILED")


def diagnose():
    result = collect()
    print(f"[라이브 GPO] boot={result['boot_time']} computer_sessions={result['session_count']} "
          f"ActivityID={result['activity_id']} records={result['start_record']}..{result['end_record']} "
          "applied_gpo_count=0; 관측 PASS, History 예외 허용 아님")
    return result
