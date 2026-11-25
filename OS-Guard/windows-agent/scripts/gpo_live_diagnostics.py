"""E2E 진단 전용. 이벤트 관측 성공은 History 예외 승인 근거로 사용하지 않는다."""

from datetime import datetime
import json
from uuid import UUID
import xml.etree.ElementTree as ET

from agent.checks.common import NativeWindowsReadOnlyApi

CHANNEL = "Microsoft-Windows-GroupPolicy/Operational"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
STARTS = {4000: 8000, 4002: 8002, 4004: 8004, 4006: 8006}
# Microsoft의 사용자/컴퓨터 처리 종료 및 warning/error 분류:
# https://devblogs.microsoft.com/scripting/weekend-scripter-use-powershell-to-troubleshoot-group-policy/
# 실제 VM의 버전·필드는 아래 런타임 검사에서 별도로 확인한다.
USER_STARTS = {4001: 8001, 4003: 8003, 4005: 8005, 4007: 8007}
ALL_STARTS = {**STARTS, **USER_STARTS}
FAILED_ENDS = frozenset({6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
                        7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007})
# 세션 증명에 실제로 사용하는 역할만 명시한다. 번호 대역과 IsMachine은
# 세션 경계를 뜻하지 않으며 4117/5351 같은 일반 알림에도 나타날 수 있다.
SESSION_EVENTS = frozenset({*ALL_STARTS, *ALL_STARTS.values(), *FAILED_ENDS, 5117, 5126, 5312, 5313})
SESSION_EVIDENCE_FIELDS = frozenset({
    "PolicyActivityId", "GPOInfoList", "NumberOfGPOsDownloaded", "NumberOfGPOsApplicable",
    "IsDomainJoined", "IsConnectivityFailure", "SessionTimeElapsedInMilliseconds",
})


def session_evidence(row):
    if row["id"] in SESSION_EVENTS:
        return True
    # 미지원 이벤트가 정책 적용/세션 증거 필드를 담으면 일반 알림으로 버리지 않는다.
    # ActivityID가 있어도 그 이벤트 의미를 지원하기 전에는 안전하게 차단한다.
    if row["data"].keys() & SESSION_EVIDENCE_FIELDS:
        fail("GPO_EVENT_ROLE_UNSUPPORTED")
    return False


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
    context = {"stage": "SNAPSHOT_HEADER", "event_id": None, "record_id": None}
    try:
        return _validate(snapshot, context)
    except LiveDiagnosticError as exc:
        exc.diagnostic = {**context, "exception_type": type(exc).__name__}
        raise
    except (KeyError, TypeError, ValueError, AttributeError, ET.ParseError) as cause:
        exc = LiveDiagnosticError("GPO_SNAPSHOT_INVALID")
        # 예외·이벤트 원문은 출력하지 않고, 식별자는 파싱된 정수만 남긴다.
        exc.diagnostic = {**context, "exception_type": type(cause).__name__}
        raise exc from None


def _validate(snapshot, context):
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
        context.update(stage="EVENT_XML", event_id=None, record_id=None)
        node = safe_xml(raw)
        system = node.find("e:System", NS)
        context["stage"] = "EVENT_IDENTITY"
        context["event_id"] = int(system.findtext("e:EventID", namespaces=NS))
        context["record_id"] = int(system.findtext("e:EventRecordID", namespaces=NS))
        context["stage"] = "EVENT_PROVIDER"
        provider = system.find("e:Provider", NS)
        if (provider.get("Name") != "Microsoft-Windows-GroupPolicy"
                or provider.get("Guid", "").lower() != "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}"
                or system.findtext("e:Channel", namespaces=NS) != CHANNEL):
            fail("GPO_PROVIDER_MISMATCH")
        data = {}
        context["stage"] = "EVENT_DATA"
        for field in node.findall("e:EventData/e:Data", NS):
            name = field.get("Name")
            if not name or name in data:
                fail("GPO_DUPLICATE_FIELD")
            data[name] = field.text or ""
        context["stage"] = "EVENT_FIELDS"
        row = {"id": context["event_id"],
               "version": int(system.findtext("e:Version", namespaces=NS)),
               "record": context["record_id"],
               "time": date(system.find("e:TimeCreated", NS).get("SystemTime")),
               "level": int(system.findtext("e:Level", namespaces=NS)), "data": data}
        context["stage"] = "EVENT_SAFETY"
        if not 1 <= row["id"] <= 65535 or row["record"] <= 0 or row["version"] < 0:
            fail("GPO_EVENT_IDENTITY_INVALID")
        if not boot <= row["time"] <= observed:
            fail("GPO_EVENT_OUTSIDE_CURRENT_BOOT")
        if row["level"] not in {0, 4, 5}:
            fail("GPO_WARNING_OR_ERROR")
        if row["id"] in FAILED_ENDS:
            fail("GPO_SESSION_FAILED")
        if "ErrorCode" in data and int(data["ErrorCode"], 0) != 0:
            fail("GPO_SESSION_FAILED")
        if row["id"] in {5117, 5126, 5312, 5313} and row["version"] != 0:
            fail("GPO_EVENT_VERSION_UNSUPPORTED")
        context["stage"] = "EVENT_ACTIVITY"
        required = session_evidence(row)
        correlation = system.find("e:Correlation", NS)
        activity = correlation.get("ActivityID") if correlation is not None else None
        if not activity or not activity.strip():
            if required:
                fail("GPO_ACTIVITY_MISSING")
            # 6339 등 비세션 이벤트도 버리지 않는다. 위 안전검증과 아래 시간/RecordID
            # 검증에는 포함하되 None은 어떤 세션의 증거로도 연결하지 않는다.
            row["activity"] = None
        else:
            try:
                row["activity"] = str(UUID(activity.strip("{}")))
            except ValueError:
                fail("GPO_ACTIVITY_INVALID")
        rows.append(row)
    context.update(stage="SESSION_SELECTION", event_id=None, record_id=None)
    rows.sort(key=lambda row: row["record"])
    if len({r["record"] for r in rows}) != len(rows) or any(a["time"] > b["time"] for a, b in zip(rows, rows[1:])):
        fail("GPO_EVENT_ORDER_INVALID")
    if rows[-1]["record"] != snapshot["after_record"]:
        fail("GPO_QUERY_INCOMPLETE")
    all_starts = [r for r in rows if r["id"] in ALL_STARTS]
    for row in rows:
        if row["id"] in ALL_STARTS or row["id"] in ALL_STARTS.values():
            expected_machine = row["id"] in STARTS or row["id"] in STARTS.values()
            if machine(row) != expected_machine:
                fail("GPO_SESSION_SCOPE_MISMATCH")
    starts = [r for r in all_starts if r["id"] in STARTS]
    if not starts or not any(r["id"] == 4000 for r in starts):
        fail("GPO_CURRENT_BOOT_START_MISSING")
    if len({r["activity"] for r in all_starts}) != len(all_starts):
        fail("GPO_SESSION_START_DUPLICATE")
    activities = {r["activity"]: machine(r) for r in all_starts}
    for row in rows:
        if row["id"] in {*ALL_STARTS.values(), 5117, 5126, 5312, 5313}:
            if row["activity"] not in activities:
                fail("GPO_ORPHAN_SESSION_EVENT")
            if row["id"] not in {5312, 5313} and machine(row) != activities[row["activity"]]:
                fail("GPO_SESSION_SCOPE_MISMATCH")
    # 사용자 세션도 실패·미완료를 숨기지 않는다. 최신 컴퓨터 증거 선택은 별도로 한다.
    for start in all_starts:
        context.update(stage="SESSION_COMPLETION", event_id=start["id"], record_id=start["record"])
        group = [r for r in rows if r["activity"] == start["activity"]]
        end = [r for r in group if r["id"] == ALL_STARTS[start["id"]]]
        final = [r for r in group if r["id"] == 5117]
        if len(end) != 1 or len(final) != 1:
            fail("GPO_MACHINE_SESSION_INCOMPLETE" if machine(start) else "GPO_USER_SESSION_INCOMPLETE")
        if not start["record"] < end[0]["record"] < final[0]["record"] or final[0] != group[-1]:
            fail("GPO_SESSION_ORDER_INVALID")
        if (machine(end[0]) != machine(start) or machine(final[0]) != machine(start)
                or int(end[0]["data"]["ErrorCode"], 0) != 0):
            fail("GPO_SESSION_FAILED")
        if start["data"]["IsDomainJoined"] != "false" or end[0]["data"]["IsConnectivityFailure"] != "false":
            fail("GPO_DOMAIN_OR_CONNECTIVITY_FAILURE")
        if str(UUID(start["data"]["PolicyActivityId"].strip("{}"))) != start["activity"]:
            fail("GPO_ACTIVITY_MISMATCH")
        if not machine(start):
            # 사용자 세션도 적용 정책이나 파싱 실패를 숨기지 않는다. 컴퓨터의
            # 필수 6개 증거 검증은 아래에서 별도로 유지한다.
            for row in group:
                if row["id"] == 5126 and any(int(row["data"][key]) != 0 for key in (
                        "NumberOfGPOsDownloaded", "NumberOfGPOsApplicable")):
                    fail("GPO_USER_APPLIED_POLICY_FOUND")
                if row["id"] == 5312 and row["data"]["GPOInfoList"].strip():
                    fail("GPO_USER_APPLIED_POLICY_FOUND")
    latest = starts[-1]
    context.update(stage="LATEST_SESSION", event_id=latest["id"], record_id=latest["record"])
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
    context["stage"] = "APPLIED_GPO_VALIDATION"
    if any(row["version"] != 0 for row in (count, applied, excluded, selected[-1])):
        fail("GPO_EVENT_VERSION_UNSUPPORTED")
    if not machine(count) or any(int(count["data"][key]) != 0 for key in ("NumberOfGPOsDownloaded", "NumberOfGPOsApplicable")):
        fail("GPO_APPLIED_POLICY_FOUND")
    if applied["data"]["GPOInfoList"].strip():
        fail("GPO_APPLIED_POLICY_FOUND")
    context.update(stage="LOCAL_GPO_XML", event_id=excluded["id"], record_id=excluded["record"])
    gpo = safe_xml(excluded["data"]["GPOInfoList"])
    # 번역된 Name/DescriptionString은 판단에 사용하지 않는다.
    if (gpo.tag != "GPO" or gpo.findtext("SOM") != "Local" or gpo.findtext("Version") != "0"
            or gpo.findtext("Reason") != "NOTAPPLIED-EMPTY" or gpo.findall(".//GPO")
            or any(len(gpo.findall(key)) != 1 for key in ("SOM", "Version", "Reason"))):
        fail("GPO_LOCAL_POLICY_NOT_EMPTY")
    return {"boot_time": snapshot["boot_time"], "session_count": len(starts),
            "user_session_count": len(all_starts) - len(starts),
            "activity_id": latest["activity"], "start_record": latest["record"],
            "end_record": selected[-1]["record"], "applied_gpo_count": 0}


def event_inventory(snapshot):
    """모든 이벤트의 ID/버전/필드 이름을 묶는다. 계정명·필드 값·XML은 반환하지 않는다.

    검증 통과와 무관한 관측 목록이며 미지원 유형을 한 번에 찾기 위한 자료다.
    """
    entries = []
    scopes = {}
    for raw in snapshot.get("events", []):
        try:
            node = safe_xml(raw)
            system = node.find("e:System", NS)
            eid = int(system.findtext("e:EventID", namespaces=NS))
            record = int(system.findtext("e:EventRecordID", namespaces=NS))
            version = int(system.findtext("e:Version", namespaces=NS))
            level = int(system.findtext("e:Level", namespaces=NS))
            correlation = system.find("e:Correlation", NS)
            activity = correlation.get("ActivityID", "") if correlation is not None else ""
            fields = {f.get("Name"): f.text or "" for f in node.findall("e:EventData/e:Data", NS)}
            row = {"id": eid, "data": fields}
            try:
                required = session_evidence(row)
                role = "SESSION" if required else "GENERAL"
                reason = None
            except LiveDiagnosticError as exc:
                role, reason = "UNSUPPORTED", exc.reason_code
            if eid in ALL_STARTS or eid in ALL_STARTS.values():
                role = "COMPUTER" if eid in STARTS or eid in STARTS.values() else "USER"
                if eid in ALL_STARTS:
                    scopes[activity] = role
            entries.append({"event_id": eid, "version": version, "level": level,
                            "record_id": record, "activity_present": bool(activity.strip()),
                            "fields": sorted(k for k in fields if k), "role": role,
                            "reason_code": reason, "_activity": activity})
        except (LiveDiagnosticError, AttributeError, TypeError, ValueError, ET.ParseError) as exc:
            entries.append({"role": "UNPARSEABLE", "exception_type": type(exc).__name__})
    grouped = {}
    for entry in entries:
        activity = entry.pop("_activity", None)
        if entry["role"] == "SESSION":
            entry["role"] = scopes.get(activity, "UNRESOLVED_SESSION")
        record = entry.pop("record_id", None)
        key = json.dumps(entry, sort_keys=True)
        if key not in grouped:
            grouped[key] = {**entry, "count": 0, "first_record": record, "last_record": record}
        group = grouped[key]
        group["count"] += 1
        if record is not None:
            group["first_record"] = min(group["first_record"], record)
            group["last_record"] = max(group["last_record"], record)
    return list(grouped.values())


def collect(*, detailed=False):
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
        if detailed:
            # 실패 유형이 여럿이어도 목록 전체를 먼저 보여 준다. 이것은 PASS 판정이 아니다.
            print("[GPO 이벤트 목록] 관측 전용; 안전성 검증 전")
            for entry in event_inventory(rows[0]):
                print(json.dumps(entry, ensure_ascii=True, sort_keys=True))
        return validate(rows[0])
    except LiveDiagnosticError:
        raise
    except Exception as cause:
        exc = LiveDiagnosticError("GPO_LIVE_QUERY_FAILED")
        exc.diagnostic = {"stage": "LIVE_QUERY", "event_id": None, "record_id": None,
                          "exception_type": type(cause).__name__}
        raise exc from None


def diagnose():
    result = collect(detailed=True)
    print(f"[라이브 GPO] boot={result['boot_time']} computer_sessions={result['session_count']} "
          f"ActivityID={result['activity_id']} records={result['start_record']}..{result['end_record']} "
          f"user_sessions={result['user_session_count']} "
          "applied_gpo_count=0; 관측 PASS, History 예외 허용 아님")
    return result
