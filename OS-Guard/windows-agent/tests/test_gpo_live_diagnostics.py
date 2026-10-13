from copy import deepcopy
import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import gpo_live_diagnostics as live
from tests.test_hardening_e2e import script

URI = live.NS["e"]
ACTIVITY = "{6b0356cc-2950-422e-a1a3-5f42d66aaaf2}"


def event(event_id, record, fields, version=0, activity=ACTIVITY, level=4):
    root = ET.Element("Event", xmlns=URI)
    system = ET.SubElement(root, "System")
    ET.SubElement(system, "Provider", Name="Microsoft-Windows-GroupPolicy", Guid="{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}")
    for key, value in (("EventID", event_id), ("Version", version), ("Level", level), ("EventRecordID", record), ("Channel", live.CHANNEL)):
        ET.SubElement(system, key).text = str(value)
    ET.SubElement(system, "TimeCreated", SystemTime="2026-10-13T06:00:19Z")
    ET.SubElement(system, "Correlation", ActivityID=activity)
    data = ET.SubElement(root, "EventData")
    for key, value in fields.items():
        ET.SubElement(data, "Data", Name=key).text = str(value)
    return ET.tostring(root, encoding="unicode")


def snapshot():
    events = [
        event(4000, 10, {"PolicyActivityId": ACTIVITY, "IsMachine": "1", "IsDomainJoined": "false"}, 1),
        event(5126, 15, {"IsMachine": "true", "NumberOfGPOsDownloaded": 0, "NumberOfGPOsApplicable": 0}),
        event(5312, 16, {"GPOInfoList": ""}),
        event(5313, 18, {"GPOInfoList": '<GPO ID="translated"><Name>번역된 이름</Name><Version>0</Version><SOM>Local</SOM><Reason>NOTAPPLIED-EMPTY</Reason></GPO>'}),
        event(8000, 20, {"IsMachine": "1", "ErrorCode": 0, "IsConnectivityFailure": "false"}, 1),
        event(5117, 21, {"IsMachine": "true", "SessionTimeElapsedInMilliseconds": 79})]
    return {"boot_time": "2026-10-13T05:59:00Z", "observed_at": "2026-10-13T06:01:00Z",
            "log_enabled": True, "clear_check_verified": True, "clear_count": 0,
            "truncated": False, "before_record": 21, "after_record": 21, "events": events}


class LiveGpoTests(unittest.TestCase):
    def test_verified_zero_gpos_and_record_gaps_are_valid(self):
        result = live.validate(snapshot())
        self.assertEqual(result["applied_gpo_count"], 0)
        self.assertEqual(result["session_count"], 1)

    def test_missing_fields_events_and_unknown_versions_fail(self):
        for index in range(6):
            data = snapshot()
            data["events"].pop(index)
            with self.subTest(index=index), self.assertRaises(live.LiveDiagnosticError):
                live.validate(data)
        data = snapshot()
        data["events"][0] = data["events"][0].replace("<Version>1</Version>", "<Version>2</Version>")
        with self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_applied_gpo_nonempty_local_policy_and_errors_fail(self):
        mutations = ((1, "<Data Name=\"NumberOfGPOsApplicable\">0", "<Data Name=\"NumberOfGPOsApplicable\">1"),
                     (2, '<Data Name="GPOInfoList" />', '<Data Name="GPOInfoList">GPO</Data>'),
                     (3, "NOTAPPLIED-EMPTY", "DENIED"),
                     (4, '<Data Name="ErrorCode">0', '<Data Name="ErrorCode">5'),
                     (4, "<Level>4</Level>", "<Level>3</Level>"))
        for index, old, new in mutations:
            data = snapshot()
            self.assertIn(old, data["events"][index])
            data["events"][index] = data["events"][index].replace(old, new)
            with self.subTest(index=index, old=old), self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_followup_incomplete_session_and_activity_mismatch_fail(self):
        data = snapshot()
        data["events"].append(event(4002, 22, {"IsMachine": "1", "IsDomainJoined": "false", "PolicyActivityId": "{11111111-1111-1111-1111-111111111111}"}, 1, "{11111111-1111-1111-1111-111111111111}"))
        data.update(before_record=22, after_record=22)
        with self.assertRaises(live.LiveDiagnosticError): live.validate(data)
        data = snapshot()
        data["events"][4] = data["events"][4].replace(ACTIVITY, "{11111111-1111-1111-1111-111111111111}")
        with self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_live_bounds_clear_truncation_disabled_and_query_race_fail(self):
        for change in ({"boot_time": "2026-10-13T06:00:30Z"}, {"observed_at": "2026-10-13T06:00:00Z"},
                       {"clear_count": 1}, {"clear_check_verified": False}, {"truncated": True},
                       {"log_enabled": False}, {"after_record": 22}):
            with self.subTest(change=change), self.assertRaises(live.LiveDiagnosticError): live.validate({**snapshot(), **change})

    def test_embedded_xml_entities_and_invalid_structure_fail(self):
        for fragment in ('<!DOCTYPE GPO [<!ENTITY x "bad">]><GPO />', '<GPO><GPO /></GPO>', '<broken'):
            data = snapshot()
            data["events"][3] = event(5313, 18, {"GPOInfoList": fragment})
            with self.subTest(fragment=fragment), self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_fixed_live_query_and_query_failure(self):
        with patch.object(live, "NativeWindowsReadOnlyApi") as api:
            api.return_value._run_powershell_json.return_value = [snapshot()]
            live.collect()
            query = api.return_value._run_powershell_json.call_args.args[0]
            self.assertIn("LastBootUpTime", query)
            self.assertIn("Get-WinEvent", query)
            self.assertNotIn("gpupdate", query)
            self.assertNotIn("Set-Item", query)
            api.return_value._run_powershell_json.side_effect = OSError("denied")
            with self.assertRaises(live.LiveDiagnosticError): live.collect()

    def test_failed_live_diagnosis_blocks_without_mutation(self):
        with patch.object(script, "_is_administrator", return_value=True), patch.object(script, "diagnose_live_gpo", side_effect=live.LiveDiagnosticError("GPO_MACHINE_SESSION_INCOMPLETE")), patch.object(script, "require_local_policy") as policy, patch.object(script, "get_action") as action, patch.object(script, "prepare_fail") as prepare, patch("builtins.input") as approval, redirect_stdout(io.StringIO()):
            self.assertEqual(script.main(["--code", "W-07", "--diagnose-env"]), 1)
            for unused in (policy, action, prepare, approval): unused.assert_not_called()

    def test_successful_live_diagnosis_does_not_bypass_history(self):
        with patch.object(script, "_is_administrator", return_value=True), patch.object(script, "diagnose_live_gpo", return_value={"applied_gpo_count": 0}), patch.object(script, "require_local_policy", side_effect=script.EnvironmentDiagnosticError("POLICY_HISTORY_FOUND", "POLICY_HISTORY", "unverified")), patch.object(script, "get_action") as action, redirect_stdout(io.StringIO()):
            self.assertEqual(script.main(["--code", "W-07", "--diagnose-env"]), 1)
            action.assert_not_called()
