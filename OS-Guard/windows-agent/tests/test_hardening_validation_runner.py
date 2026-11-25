import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import run_hardening_validation as runner


class ValidationRunnerTests(unittest.TestCase):
    def test_default_only_diagnoses_and_records_each_allowlisted_item(self):
        with TemporaryDirectory() as temp, patch.object(runner, "ROOT", Path(temp)), \
                patch.object(runner.e2e, "main", return_value=1) as call, \
                patch("builtins.input") as approval, redirect_stdout(io.StringIO()):
            for code in sorted(runner.e2e.SEMI_AUTO_ALLOWLIST):
                self.assertEqual(runner.main(["--code", code]), 1)
                call.assert_called_with(["--code", code, "--diagnose-env"])
            approval.assert_not_called()
            reports = list(Path(temp).rglob("*.json"))
            self.assertEqual(len(reports), 18)
            self.assertTrue(all(json.loads(p.read_text())["mode"] == "DIAGNOSE_ONLY" for p in reports))

    def test_execute_requires_snapshot_confirmation_before_delegate(self):
        with patch.object(runner.e2e, "main") as call, patch("builtins.input", return_value="no"), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["--code", "W-07", "--execute"]), 1)
            call.assert_not_called()

    def test_execute_delegates_without_bypassing_existing_approvals(self):
        with TemporaryDirectory() as temp, patch.object(runner, "ROOT", Path(temp)), \
                patch.object(runner.e2e, "main", return_value=0) as call, \
                patch("builtins.input", return_value="SNAPSHOT W-07"), redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["--code", "W-07", "--execute"]), 0)
            self.assertEqual(call.call_args_list, [
                unittest.mock.call(["--code", "W-07", "--diagnose-env"]),
                unittest.mock.call(["--code", "W-07"])])
            report = json.loads(next(Path(temp).rglob("*.json")).read_text())
            self.assertEqual(report["result"], "PASS")
            self.assertFalse(report["central_approval"])

    def test_failed_diagnosis_never_enters_execute(self):
        with TemporaryDirectory() as temp, patch.object(runner, "ROOT", Path(temp)), \
                patch.object(runner.e2e, "main", return_value=1) as delegate, \
                patch("builtins.input", return_value="SNAPSHOT W-07"), redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(["--code", "W-07", "--execute"]), 1)
            delegate.assert_called_once_with(["--code", "W-07", "--diagnose-env"])

    def test_no_batch_or_non_allowlisted_item(self):
        with patch.object(runner.e2e, "main") as call, redirect_stdout(io.StringIO()), \
                patch("sys.stderr", io.StringIO()):
            for args in (["--code", "W-01"], ["--all"], ["--code", "W-07", "--all"]):
                with self.subTest(args=args), self.assertRaises(SystemExit): runner.main(args)
            call.assert_not_called()
