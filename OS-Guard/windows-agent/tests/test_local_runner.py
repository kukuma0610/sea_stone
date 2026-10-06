import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent.local_runner import CHECK_IDS, CHECK_TITLES, _console_reason, print_report, run_checks, save_report
from agent.windows_checks import CheckObservation


class LocalRunnerTests(unittest.TestCase):
    def test_runs_all_checks_in_order_and_saves_json(self):
        def collector(item_id, api):
            return CheckObservation(item_id, "PASS", "TEST", {"masked": "a***z"}, evidence_redacted=True)

        report = run_checks(api=object(), collector=collector, system_info={"administrator": False})
        self.assertEqual([item["item_id"] for item in report["checks"]], list(CHECK_IDS))
        self.assertEqual(report["summary"], {"PASS": 64, "FAIL": 0, "NA": 0, "UNABLE": 0})
        self.assertNotIn("current_value", report["checks"][0])
        self.assertEqual(report["checks"][0]["evidence"], {"masked": "a***z"})
        with tempfile.TemporaryDirectory() as directory:
            output = save_report(report, Path(directory) / "report.json")
            self.assertTrue(output.is_file())

    def test_collector_error_is_isolated_and_later_checks_continue(self):
        def collector(item_id, api):
            if item_id == "W-02":
                raise RuntimeError("collector failed")
            return CheckObservation(item_id, "PASS", "TEST", {})

        report = run_checks(api=object(), collector=collector, system_info={"administrator": True})
        self.assertEqual(report["checks"][1]["status"], "UNABLE")
        self.assertIn("RuntimeError", report["checks"][1]["error_reason"])
        self.assertEqual(report["checks"][-1]["item_id"], "W-64")
        self.assertEqual(report["checks"][-1]["status"], "PASS")

    def test_console_output_is_compact_and_does_not_change_report(self):
        statuses = {"W-01": "PASS", "W-02": "FAIL", "W-03": "UNABLE", "W-04": "NA"}

        def collector(item_id, api):
            status = statuses.get(item_id, "PASS")
            return CheckObservation(
                item_id, status, "SHORT_REASON", {"secret_evidence": "must-not-print"},
                error_reason="collection failed" if status == "UNABLE" else None,
            )

        report = run_checks(
            api=object(), collector=collector,
            system_info={"os": "Windows", "release": "Server 2022", "windows_build": "20348", "administrator": True},
        )
        original = repr(report)
        output = StringIO()
        with redirect_stdout(output):
            print_report(report, Path("results/windows-check.json"))
        rendered = output.getvalue()

        self.assertEqual(len(CHECK_TITLES), 64)
        self.assertIn("OS: Windows Server 2022", rendered)
        self.assertIn("Build: 20348", rendered)
        self.assertIn("관리자: 예", rendered)
        self.assertIn("[PASS] W-01 Administrator 계정 이름 변경 등 보안성 강화", rendered)
        self.assertIn("[FAIL] W-02 Guest 계정 비활성화\n  사유: SHORT_REASON", rendered)
        self.assertIn("[UNABLE] W-03 불필요한 계정 제거\n  사유: 설정 수집에 실패했습니다.", rendered)
        self.assertIn("[NA] W-04 계정 잠금 임계값 설정", rendered)
        self.assertIn("PASS=61 FAIL=1 UNABLE=1 NA=1 TOTAL=64", rendered)
        self.assertNotIn("secret_evidence", rendered)
        self.assertEqual(repr(report), original)

    def test_console_reason_translation_keeps_internal_values_unchanged(self):
        reasons = {
            "KISA_W47_SCREEN_SAVER": "KISA 양호 기준을 충족하지 않습니다.",
            "SERVICE_NECESSITY_REQUIRES_MANUAL_REVIEW": "운영 환경과 업무 필요성에 대한 수동 검토가 필요합니다.",
            "REMOVABLE_MEDIA_POLICY_NOT_FOUND": "점검에 필요한 설정 또는 대상을 찾지 못했습니다.",
            "LmCompatibilityLevel registry value absent; effective default not verified":
                "레지스트리 값이 없고 실효 기본값을 확인할 수 없습니다.",
            "custom unmapped reason": "custom unmapped reason",
        }
        for internal, expected in reasons.items():
            with self.subTest(internal=internal):
                self.assertEqual(_console_reason(internal), expected)


if __name__ == "__main__":
    unittest.main()
