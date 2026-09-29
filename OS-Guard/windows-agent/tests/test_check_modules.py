import importlib
import inspect
import unittest

from agent.checks import CHECK_REGISTRY
from agent import windows_checks


class CheckModuleStructureTests(unittest.TestCase):
    def test_all_64_modules_import_with_matching_check_id(self):
        for number in range(1, 65):
            item_id = f"W-{number:02d}"
            module = importlib.import_module(f"agent.checks.w{number:02d}")
            self.assertEqual(module.CHECK_ID, item_id)
            self.assertTrue(callable(module.check))
            source = inspect.getsource(module.check)
            self.assertNotIn("_collect_check_implementation", source)
            self.assertIn("NativeWindowsReadOnlyApi", source)

    def test_registry_contains_each_check_exactly_once(self):
        expected = {f"W-{number:02d}" for number in range(1, 65)}
        self.assertEqual(set(CHECK_REGISTRY), expected)
        self.assertEqual(len(CHECK_REGISTRY), 64)
        dispatcher_source = inspect.getsource(windows_checks)
        self.assertNotIn("def _collect_check_implementation", dispatcher_source)
        self.assertNotIn('if item_id == "W-', dispatcher_source)


if __name__ == "__main__":
    unittest.main()
