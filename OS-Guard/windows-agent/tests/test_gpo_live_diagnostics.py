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


def with_user_session(start=4001, version=1):
    data = snapshot()
    activity = "{11111111-1111-1111-1111-111111111111}"
    flag = "0" if version == 1 else "false"
    data["events"].extend([
        event(start, 30, {"PolicyActivityId": activity, "IsMachine": flag,
                          "IsDomainJoined": "false"}, version, activity),
        event(5126, 31, {"IsMachine": "true", "NumberOfGPOsDownloaded": 0,
                          "NumberOfGPOsApplicable": 0}, activity=activity),
        event(5312, 32, {"GPOInfoList": ""}, activity=activity),
        event(5313, 33, {"GPOInfoList": '<GPO><Version>0</Version><SOM>Local</SOM><Reason>NOTAPPLIED-EMPTY</Reason></GPO>'}, activity=activity),
        event(live.USER_STARTS[start], 34, {"PolicyElaspedTimeInSeconds": 1, "ErrorCode": 0,
                          "PrincipalSamName": "private-user", "IsMachine": flag,
                          "IsConnectivityFailure": "false"}, version, activity),
        event(5117, 35, {"IsMachine": "false", "SessionTimeElapsedInMilliseconds": 79}, activity=activity),
    ])
    data.update(before_record=35, after_record=35)
    return data


class LiveGpoTests(unittest.TestCase):
    def test_vm_user_5126_true_uses_activity_and_independent_zero_policy_evidence(self):
        data = with_user_session()
        for index, record in enumerate((1984, 1990, 1991, 1992, 1996, 1997), 6):
            node = ET.fromstring(data["events"][index])
            node.find("e:System/e:EventRecordID", live.NS).text = str(record)
            data["events"][index] = ET.tostring(node, encoding="unicode")
        data.update(before_record=1997, after_record=1997)
        result = live.validate(data)
        self.assertEqual(result["count_flag_differences"], [{"event_id": 5126,
                          "record_id": 1990, "scope": "USER"}])
        self.assertEqual(result["end_record"], 21)
        self.assertEqual(result["applied_gpo_count"], 0)
        self.assertEqual(result["user_session_count"], 1)

    def test_user_count_flag_false_is_valid_and_invalid_or_unknown_version_fails(self):
        data = with_user_session()
        data["events"][7] = data["events"][7].replace('<Data Name="IsMachine">true', '<Data Name="IsMachine">false')
        self.assertEqual(live.validate(data)["count_flag_differences"], [])
        for old, new in (('<Data Name="IsMachine">true', '<Data Name="IsMachine">unknown'),
                         ('<Version>0</Version>', '<Version>1</Version>')):
            data = with_user_session()
            data["events"][7] = data["events"][7].replace(old, new)
            with self.subTest(old=old), self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_count_flag_difference_cannot_hide_missing_duplicate_or_wrong_activity(self):
        for kind in ("missing", "duplicate", "activity", "excluded"):
            data = with_user_session()
            if kind == "missing": data["events"].pop(8)
            elif kind == "duplicate":
                data["events"].insert(8, data["events"][7].replace('<EventRecordID>31', '<EventRecordID>36'))
                data.update(before_record=36, after_record=36)
            elif kind == "activity":
                data["events"][7] = data["events"][7].replace(
                    "{11111111-1111-1111-1111-111111111111}", ACTIVITY)
            else: data["events"][9] = data["events"][9].replace("NOTAPPLIED-EMPTY", "DENIED")
            with self.subTest(kind=kind), self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_boundary_scope_disagreement_still_reports_exact_event(self):
        data = with_user_session()
        data["events"][-2] = data["events"][-2].replace('<Data Name="IsMachine">0', '<Data Name="IsMachine">1')
        with self.assertRaises(live.LiveDiagnosticError) as caught: live.validate(data)
        self.assertEqual(caught.exception.reason_code, "GPO_SESSION_SCOPE_MISMATCH")
        self.assertEqual(caught.exception.diagnostic["event_id"], 8001)
        self.assertEqual(caught.exception.diagnostic["record_id"], 34)

    def test_unverified_computer_count_flag_conflict_stays_blocked(self):
        data = snapshot()
        data["events"][1] = data["events"][1].replace('<Data Name="IsMachine">true', '<Data Name="IsMachine">false')
        with self.assertRaises(live.LiveDiagnosticError) as caught: live.validate(data)
        self.assertEqual(caught.exception.reason_code, "GPO_SESSION_SCOPE_MISMATCH")

    def test_reported_49_events_22_ids_are_not_classified_by_id_ranges(self):
        # ID/개수와 이미 제공된 필드만 재현한다. 미제공 원본 XML을 대신하지 않는다.
        counts = {4000: 1, 4001: 1, 4115: 1, 4116: 1, 4117: 2, 4126: 2,
                  5116: 1, 5117: 2, 5126: 2, 5257: 2, 5311: 2, 5312: 2,
                  5313: 2, 5320: 9, 5321: 1, 5324: 5, 5340: 2, 5351: 4,
                  6338: 4, 6339: 1, 8000: 1, 8001: 1}
        data = with_user_session()
        record = 40
        for eid, count in counts.items():
            if eid in live.SESSION_EVENTS:
                continue
            for _ in range(count):
                fields = ({"IsMachine": "true", "WinlogonReturnTimeElapsedInMilliseconds": 12}
                          if eid == 5351 else {})
                data["events"].append(event(eid, record, fields, activity=""))
                record += 1
        data.update(before_record=record-1, after_record=record-1)
        self.assertEqual(len(data["events"]), 49)
        inventory = live.event_inventory(data)
        self.assertEqual({e["event_id"] for e in inventory}, set(counts))
        for eid, count in counts.items():
            self.assertEqual(sum(e["count"] for e in inventory if e["event_id"] == eid), count)
        self.assertTrue(any(e["event_id"] == 5351 and e["is_machine"] is True for e in inventory))
        self.assertEqual(live.validate(data)["user_session_count"], 1)
        # 일반 이벤트가 있어도 필요한 정책 증거가 없으면 통과하지 않는다.
        data["events"].pop(2)
        with self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_all_computer_user_start_pair_combinations(self):
        for computer_start in live.STARTS:
            for user_start in live.USER_STARTS:
                data = with_user_session(user_start)
                if computer_start != 4000:
                    # 부팅 세션은 남기고 그 뒤의 컴퓨터 처리 세션을 추가한다.
                    extra = snapshot()["events"]
                    for raw in extra:
                        node = ET.fromstring(raw)
                        system = node.find("e:System", live.NS)
                        eid = system.find("e:EventID", live.NS)
                        if eid.text == "4000": eid.text = str(computer_start)
                        if eid.text == "8000": eid.text = str(live.STARTS[computer_start])
                        rec = system.find("e:EventRecordID", live.NS)
                        rec.text = str(int(rec.text) + 40)
                        xml = ET.tostring(node, encoding="unicode").replace(ACTIVITY,
                            "{22222222-2222-2222-2222-222222222222}")
                        data["events"].append(xml)
                    data.update(before_record=61, after_record=61)
                with self.subTest(computer=computer_start, user=user_start):
                    result = live.validate(data)
                    self.assertEqual(result["user_session_count"], 1)
                    self.assertEqual(result["session_count"], 1 if computer_start == 4000 else 2)

    def test_all_user_session_pairs_are_separate_from_computer_evidence(self):
        for start in live.USER_STARTS:
            for version in (0, 1):
                with self.subTest(start=start, version=version):
                    result = live.validate(with_user_session(start, version))
                    self.assertEqual(result["session_count"], 1)
                    self.assertEqual(result["user_session_count"], 1)
                    self.assertEqual(result["start_record"], 10)
                    self.assertEqual(result["end_record"], 21)

    def test_user_error_missing_activity_and_scope_mismatch_are_blocked(self):
        for old, new in (('<Data Name="ErrorCode">0', '<Data Name="ErrorCode">5'),
                         ('ActivityID="{11111111-1111-1111-1111-111111111111}"', 'ActivityID=""'),
                         ('<Data Name="IsMachine">0', '<Data Name="IsMachine">1'),
                         ('<Version>1</Version>', '<Version>2</Version>')):
            data = with_user_session()
            self.assertIn(old, data["events"][-2])
            data["events"][-2] = data["events"][-2].replace(old, new)
            with self.subTest(old=old), self.assertRaises(live.LiveDiagnosticError):
                live.validate(data)

    def test_user_orphan_incomplete_duplicate_and_cross_session_fail(self):
        for index in (6, -2, -1):
            data = with_user_session()
            data["events"].pop(index)
            with self.subTest(index=index), self.assertRaises(live.LiveDiagnosticError):
                live.validate(data)
        data = with_user_session()
        data["events"][-2] = data["events"][-2].replace(
            "{11111111-1111-1111-1111-111111111111}", ACTIVITY)
        with self.assertRaises(live.LiveDiagnosticError): live.validate(data)

    def test_user_session_cannot_replace_computer_current_boot_session(self):
        data = with_user_session()
        data["events"] = data["events"][6:]
        with self.assertRaises(live.LiveDiagnosticError) as caught:
            live.validate(data)
        self.assertEqual(caught.exception.reason_code, "GPO_CURRENT_BOOT_START_MISSING")

    def test_user_applied_policy_is_not_hidden_by_computer_zero_policy(self):
        for index, old, new in (
            (7, '<Data Name="NumberOfGPOsApplicable">0', '<Data Name="NumberOfGPOsApplicable">1'),
            (8, '<Data Name="GPOInfoList" />', '<Data Name="GPOInfoList">policy</Data>')):
            data = with_user_session()
            self.assertIn(old, data["events"][index])
            data["events"][index] = data["events"][index].replace(old, new)
            with self.subTest(index=index), self.assertRaises(live.LiveDiagnosticError) as caught:
                live.validate(data)
            self.assertEqual(caught.exception.reason_code, "GPO_USER_APPLIED_POLICY_FOUND")

    def test_warning_error_end_ids_fail_even_if_level_is_information(self):
        for eid in live.FAILED_ENDS:
            data = snapshot()
            data["events"].append(event(eid, 40, {"ErrorCode": 0}))
            data.update(before_record=40, after_record=40)
            with self.subTest(eid=eid), self.assertRaises(live.LiveDiagnosticError):
                live.validate(data)

    def test_inventory_reports_all_types_without_account_or_field_values(self):
        data = with_user_session()
        data["events"].extend([event(5351, 40, {"IsMachine": "true"}, activity=""),
                                event(9999, 41, {"GPOInfoList": "private-policy"})])
        result = live.event_inventory(data)
        self.assertTrue(any(e["event_id"] == 8001 and e["role"] == "USER" for e in result))
        self.assertTrue(any(e["event_id"] == 5351 and e["role"] == "GENERAL" for e in result))
        self.assertTrue(any(e["event_id"] == 9999 and e["role"] == "UNSUPPORTED" for e in result))
        self.assertNotIn("private-user", str(result))
        self.assertNotIn("private-policy", str(result))
        self.assertIn("PrincipalSamName", str(result))

    def test_detailed_query_lists_all_types_before_failing_validation(self):
        data = with_user_session()
        data["events"][-2] = data["events"][-2].replace('<Data Name="ErrorCode">0', '<Data Name="ErrorCode">5')
        output = io.StringIO()
        with patch.object(live, "NativeWindowsReadOnlyApi") as api, redirect_stdout(output):
            api.return_value._run_powershell_json.return_value = [data]
            with self.assertRaises(live.LiveDiagnosticError): live.collect(detailed=True)
        self.assertIn('"event_id": 8001', output.getvalue())
        self.assertIn('"event_id": 4000', output.getvalue())
        self.assertNotIn("private-user", output.getvalue())

    def test_missing_activity_is_classified_not_attribute_error(self):
        for event_id in (*live.STARTS, *live.STARTS.values(), 5117, 5126, 5312, 5313):
            for correlation in ("", "<Correlation />", '<Correlation ActivityID="" />'):
                data = snapshot()
                raw = event(event_id, 19, {"InfoDescription": "secret-not-for-output"})
                data["events"].insert(4, raw.replace(
                    f'<Correlation ActivityID="{ACTIVITY}" />', correlation))
                with self.subTest(event_id=event_id, correlation=correlation):
                    with self.assertRaises(live.LiveDiagnosticError) as caught:
                        live.validate(data)
                    self.assertEqual(caught.exception.reason_code, "GPO_ACTIVITY_MISSING")
                    self.assertEqual(caught.exception.diagnostic["event_id"], event_id)
                    self.assertEqual(caught.exception.diagnostic["record_id"], 19)
                    self.assertEqual(caught.exception.diagnostic["stage"], "EVENT_ACTIVITY")

    def test_vm_6339_without_activity_is_not_session_evidence(self):
        # VM에서 보고된 EventID/RecordID/상관관계 부재만 재현한다.
        # 원본 6339 XML은 아직 없으므로 payload 의미는 가정하지 않는다.
        for event_id in (4117, 5324, 5351, 6338, 6339, 5320):
            for correlation in ("", "<Correlation />", '<Correlation ActivityID="" />'):
                data = snapshot()
                fields = ({"IsMachine": "true", "WinlogonReturnTimeElapsedInMilliseconds": 12}
                          if event_id == 5351 else {})
                raw = event(event_id, 1948, fields)
                data["events"].append(raw.replace(f'<Correlation ActivityID="{ACTIVITY}" />', correlation))
                data.update(before_record=1948, after_record=1948)
                with self.subTest(event_id=event_id, correlation=correlation):
                    result = live.validate(data)
                    self.assertEqual(result["session_count"], 1)
                    self.assertEqual(result["end_record"], 21)
                    self.assertEqual(result["activity_id"], ACTIVITY.strip("{}").lower())

    def test_uncorrelated_event_does_not_hide_errors_or_invalid_metadata(self):
        raw = event(6339, 1948, {"ErrorCode": 0}, activity="")
        mutations = (
            ("<Level>4</Level>", "<Level>3</Level>"),
            ('<Data Name="ErrorCode">0', '<Data Name="ErrorCode">5'),
            ('<Data Name="ErrorCode">0', '<Data Name="ErrorCode">invalid'),
            ("2026-10-13T06:00:19Z", "2026-10-12T06:00:19Z"),
            ("<EventRecordID>1948</EventRecordID>", "<EventRecordID>21</EventRecordID>"),
            ("<EventRecordID>1948</EventRecordID>", "<EventRecordID>0</EventRecordID>"),
            ("Microsoft-Windows-GroupPolicy", "Other-Provider"),
            (live.CHANNEL, "Other-Channel"),
            ("<EventID>6339</EventID>", "<EventID>0</EventID>"),
        )
        for old, new in mutations:
            data = snapshot()
            self.assertIn(old, raw)
            data["events"].append(raw.replace(old, new))
            data.update(before_record=1948, after_record=1948)
            with self.subTest(old=old), self.assertRaises(live.LiveDiagnosticError):
                live.validate(data)

    def test_uncorrelated_policy_fields_cannot_be_treated_as_general_event(self):
        for fields in ({"GPOInfoList": "GPO"},
                       {"NumberOfGPOsApplicable": 1}, {"PolicyActivityId": ACTIVITY}):
            data = snapshot()
            data["events"].append(event(6339, 1948, fields, activity=""))
            data.update(before_record=1948, after_record=1948)
            with self.subTest(fields=fields), self.assertRaises(live.LiveDiagnosticError) as caught:
                live.validate(data)
            self.assertEqual(caught.exception.reason_code, "GPO_EVENT_ROLE_UNSUPPORTED")

    def test_unknown_policy_evidence_is_rejected_even_with_activity(self):
        for activity in (ACTIVITY, ""):
            for fields in ({"NumberOfGPOsApplicable": 0}, {"IsDomainJoined": "false"},
                           {"SessionTimeElapsedInMilliseconds": 1}):
                data = snapshot()
                data["events"].append(event(9999, 1948, fields, activity=activity))
                data.update(before_record=1948, after_record=1948)
                with self.subTest(activity=activity, fields=fields), self.assertRaises(live.LiveDiagnosticError) as caught:
                    live.validate(data)
                self.assertEqual(caught.exception.reason_code, "GPO_EVENT_ROLE_UNSUPPORTED")

    def test_general_is_machine_does_not_assert_session_or_hide_errors(self):
        for event_id in (4117, 5324, 5351, 6338, 6339):
            for fields, level in (({"IsMachine": "1"}, 4),
                                  ({"IsMachine": "1", "ErrorCode": 5}, 4),
                                  ({"IsMachine": "1"}, 3)):
                data = snapshot()
                data["events"].append(event(event_id, 1948, fields, activity="", level=level))
                data.update(before_record=1948, after_record=1948)
                with self.subTest(event_id=event_id, fields=fields, level=level):
                    if level == 4 and "ErrorCode" not in fields:
                        self.assertEqual(live.validate(data)["session_count"], 1)
                    else:
                        with self.assertRaises(live.LiveDiagnosticError):
                            live.validate(data)

    def test_general_event_cannot_complete_missing_or_followup_session(self):
        for remove_end in (True, False):
            data = snapshot()
            if remove_end:
                data["events"].pop(4)
            else:
                data["events"].append(event(4002, 22, {"IsMachine": "1"}, version=1))
            data["events"].append(event(6339, 1948, {}, activity=""))
            data.update(before_record=1948, after_record=1948)
            with self.subTest(remove_end=remove_end), self.assertRaises(live.LiveDiagnosticError):
                live.validate(data)

    def test_invalid_activity_and_parser_exception_have_safe_context(self):
        for old, new, reason, stage, kind in (
            (ACTIVITY, "not-a-guid", "GPO_ACTIVITY_INVALID", "EVENT_ACTIVITY", "LiveDiagnosticError"),
            ("<Version>1</Version>", "<Version>private-token</Version>",
             "GPO_SNAPSHOT_INVALID", "EVENT_FIELDS", "ValueError")):
            data = snapshot()
            data["events"][0] = data["events"][0].replace(old, new)
            with self.subTest(stage=stage), self.assertRaises(live.LiveDiagnosticError) as caught:
                live.validate(data)
            self.assertEqual(caught.exception.reason_code, reason)
            self.assertEqual(caught.exception.diagnostic["stage"], stage)
            self.assertEqual(caught.exception.diagnostic["exception_type"], kind)
            output = io.StringIO()
            with redirect_stdout(output):
                script.report_environment_exception(caught.exception, "ENVIRONMENT_CHECK_FAILED", "ENVIRONMENT")
            self.assertIn("event_id=4000 record_id=10", output.getvalue())
            self.assertNotIn("private-token", output.getvalue())

    def test_malformed_xml_and_header_report_stage_without_event_payload(self):
        for data, stage in (({**snapshot(), "events": ["<broken"]}, "EVENT_XML"),
                            ({**snapshot(), "boot_time": None}, "SNAPSHOT_HEADER")):
            with self.subTest(stage=stage), self.assertRaises(live.LiveDiagnosticError) as caught:
                live.validate(data)
            self.assertEqual(caught.exception.reason_code, "GPO_SNAPSHOT_INVALID")
            self.assertEqual(caught.exception.diagnostic["stage"], stage)

    def test_correlated_information_event_preserves_session_validation(self):
        data = snapshot()
        data["events"].insert(4, event(5320, 19, {"InfoDescription": "information"}))
        self.assertEqual(live.validate(data)["applied_gpo_count"], 0)

    def test_live_query_exception_does_not_expose_message(self):
        with patch.object(live, "NativeWindowsReadOnlyApi") as api:
            api.return_value._run_powershell_json.side_effect = OSError("private-token")
            with self.assertRaises(live.LiveDiagnosticError) as caught:
                live.collect()
        self.assertEqual(caught.exception.diagnostic["stage"], "LIVE_QUERY")
        self.assertEqual(caught.exception.diagnostic["exception_type"], "OSError")
        self.assertNotIn("private-token", str(caught.exception))

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
