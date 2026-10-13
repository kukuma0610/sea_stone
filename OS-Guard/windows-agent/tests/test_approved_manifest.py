import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agent.central import __main__ as cli
from agent.central.contract import Manifest
from agent.central.release import RegistrationRelease
from agent.checks import CHECK_REGISTRY
from tests import test_registration_cli as registration_tests


MANIFEST_PATH = Path(cli.__file__).with_name("manifest-windows-64-2026-v1.json")


class OnePollStop:
    def __init__(self): self.stopped = False
    def is_set(self): return self.stopped
    def set(self): self.stopped = True
    def wait(self, timeout): self.stopped = True; return True


class ApprovedManifestTests(unittest.TestCase):
    def test_approved_identity_schema_and_64_exact_mappings(self):
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest = Manifest(value)
        identity = RegistrationRelease()
        self.assertEqual((manifest.id, manifest.version), (identity.id, identity.version))
        self.assertEqual(value["schema_version"], "1.0")
        self.assertEqual(value["platform"], "windows")
        self.assertIs(value["simulation"], False)
        self.assertEqual(len(value["items"]), 64)
        self.assertEqual(set(manifest.items), set(CHECK_REGISTRY))
        for code, check in CHECK_REGISTRY.items():
            self.assertEqual(manifest.items[code]["module"], check.__module__)
            self.assertEqual(manifest.items[code]["actions"], ["CHECK"])

    def test_support_remains_server_2022_build_20348_amd64_only(self):
        manifest = Manifest(json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))
        os = dict(family="WINDOWS", version="10.0.20348", build="20348", architecture="AMD64")
        self.assertTrue(manifest.supports(os))
        for changes in ({"version": "10.0.17763", "build": "17763"}, {"version": "10.0.26100", "build": "26100"},
                        {"architecture": "ARM64"}, {"build": "20349"}, {"family": "UNIX"}):
            self.assertFalse(manifest.supports({**os, **changes}))

    def fixture(self):
        helper = registration_tests.RegistrationCliTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        self.assertEqual(helper.invoke(), 0)
        helper.central.calls.clear()
        helper.state.data["outbox"] = {}
        helper.central.no_task = True
        return helper

    def test_run_without_manifest_setting_starts_and_claims_204_no_check(self):
        helper = self.fixture()
        with patch.object(cli.threading, "Event", side_effect=OnePollStop):
            self.assertEqual(helper.invoke("run"), 0)
        paths = [row[0] for row in helper.central.calls]
        self.assertIn("/heartbeat", paths)
        self.assertIn("/inventory", paths)
        self.assertIn("/tasks/claim", paths)
        claim = next(row[1] for row in helper.central.calls if row[0] == "/tasks/claim")
        self.assertEqual(claim["module_version"], "windows-2026.1")
        self.assertFalse(any(path.endswith("/results") or path == "/evidence-uploads" for path in paths))

    def test_explicit_manifest_path_and_missing_file_fail_closed(self):
        helper = self.fixture()
        helper.config["manifest_file"] = str(MANIFEST_PATH)
        helper.config_path.write_text(json.dumps(helper.config), encoding="utf-8")
        with patch.object(cli.threading, "Event", side_effect=OnePollStop):
            self.assertEqual(helper.invoke("run"), 0)
        helper.central.calls.clear()
        helper.config["manifest_file"] = "missing-manifest.json"
        helper.config_path.write_text(json.dumps(helper.config), encoding="utf-8")
        self.assertEqual(helper.invoke("run"), 1)
        self.assertEqual(helper.central.calls, [])
