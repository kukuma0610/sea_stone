import tempfile
import unittest
from pathlib import Path

from agent.local_runner import CHECK_IDS, run_checks, save_report
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


if __name__ == "__main__":
    unittest.main()
