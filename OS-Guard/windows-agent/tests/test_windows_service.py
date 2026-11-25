"""Native changes are mocked. No SCM registration/OS policy changes on the development PC."""

import ctypes
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import Mock, patch
import zipfile

from agent.central.transport import CentralError
from agent.windows_service import MANIFEST_NAME, SERVICE_NAME
from agent.windows_service import installer, preflight, runtime, scm, security

SID = "S-1-5-80-1-2-3-4-5"
MANIFEST = Path(__file__).resolve().parents[1] / "agent/central" / MANIFEST_NAME


class Protector:
    def protect(self, value): return b"test-only:" + bytes(byte ^ 0xAB for byte in value)
    def unprotect(self, value):
        if not value.startswith(b"test-only:"): raise ValueError()
        return bytes(byte ^ 0xAB for byte in value[10:])


class Stop:
    def __init__(self, after=1): self.done = False; self.after = after; self.waits = []
    def is_set(self): return self.done
    def set(self): self.done = True
    def wait(self, delay):
        self.waits.append(delay)
        if len(self.waits) >= self.after: self.done = True
        return self.done


class FakeSCM:
    def __init__(self): self.current = None; self.calls = []; self.fail_start = False
    def query(self): return self.current
    def create(self, binary, account):
        self.calls.append("create")
        self.current = {"binary": binary, "account": account, "state": 1, "start": 2}
    def start(self):
        self.calls.append("start")
        if self.fail_start: raise security.LocalError("SERVICE_START_FAILED")
        self.current["state"] = 4
    def stop(self): self.calls.append("stop")
    def delete(self): self.calls.append("delete"); self.current = None


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        observation = patch.object(preflight, "service_observation", return_value={"state": "OBSERVED", "scm_state": 4})
        observation.start()
        self.addCleanup(observation.stop)
        privileges = patch.object(preflight, "privilege_observation", return_value={"SeRestorePrivilege": {"present": False, "enabled": False}})
        privileges.start()
        self.addCleanup(privileges.stop)
        self.root = Path(self.temp.name)
        self.install_root = self.root / "program" / "OS Guard Development Agent"
        self.data_root = self.root / "data" / "OS Guard Development Agent"
        self.install_root.parent.mkdir(); self.data_root.parent.mkdir()
        self.config = {"format": 1, "candidate": "virtual", "service_sid": SID, "account_sid": SID,
                       "install_root": str(self.install_root), "data_root": str(self.data_root),
                       "manifest_path": str(self.install_root / "_internal/agent/central" / MANIFEST_NAME),
                       "transport_enabled": False, "central_config": None}
        self.fake = FakeSCM()
        self.engine = installer.LocalInstaller(self.fake, roots=(self.install_root, self.data_root), acl=lambda *a, **k: None,
                                               sid_lookup=lambda value: SID, supported=lambda: True)
        self.archive = self.root / "payload.zip"
        self.make_payload()

    def make_payload(self, extra=None):
        files = {"os-guard-agent-service.exe": b"FAKE_TEST_BINARY", "_internal/agent/central/" + MANIFEST_NAME: MANIFEST.read_bytes()}
        if extra: files.update(extra)
        index = {"development_unsigned": True, "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
        with zipfile.ZipFile(self.archive, "w") as bundle:
            for name, raw in files.items(): bundle.writestr(name, raw)
            bundle.writestr("payload-manifest.json", json.dumps(index))

    def install(self): return self.engine.install(self.archive, candidate="virtual", accept_development=True)

    def ready(self):
        return {"observations": {"identity": {"state": "PASS"}, "dpapi": {"state": "PASS"},
                                 "os": {"supported": True}, "manifest": {"items": 64}, "integrity": {"checksum_match": True},
                                 "product_io": {"state": "PASS"}, "service": {"state": "OBSERVED"}}}

    def test_fresh_install_no_enrollment_or_transport(self):
        result = self.install()
        self.assertEqual(result["state"], "INSTALLED_LOCAL_ONLY")
        with patch.object(runtime, "known_roots", return_value=(self.install_root, self.data_root)):
            config = runtime.load_config(self.install_root / "service-local.json")
        self.assertIs(config["transport_enabled"], False)
        self.assertIsNone(config["central_config"])
        self.assertEqual(self.fake.calls, ["create", "start"])
        self.assertNotEqual(self.fake.current["account"], "LocalSystem")
        self.assertTrue(preflight.integrity(self.install_root)["checksum_match"])
        self.assertIs(preflight.integrity(self.install_root)["commercial_approved"], False)

    def test_candidate_and_unsigned_consent_required(self):
        for candidate, consent in ((None, True), ("LocalSystem", True), ("virtual", False)):
            with self.subTest(candidate=candidate), self.assertRaises(security.LocalError):
                self.engine.install(self.archive, candidate=candidate, accept_development=consent)
        self.assertFalse(self.install_root.exists())

    def test_local_service_candidate_is_explicit_not_default(self):
        self.engine.install(self.archive, candidate="local-service", accept_development=True)
        self.assertEqual(self.fake.current["account"], "NT AUTHORITY\\LocalService")
        self.assertEqual(json.loads((self.install_root / "service-local.json").read_text())["candidate"], "local-service")

    def test_unsupported_os_does_not_install(self):
        self.engine.supported = lambda: False
        with self.assertRaises(security.LocalError): self.install()
        self.assertFalse(self.data_root.exists())

    def test_payload_identity_mismatch_is_rejected(self):
        changed = json.loads(MANIFEST.read_text())
        changed["module_version"] = "another-release"
        self.make_payload({"_internal/agent/central/" + MANIFEST_NAME: json.dumps(changed).encode()})
        with self.assertRaises(security.LocalError): self.install()
        self.assertEqual(self.fake.calls, [])

    def test_idempotent_reinstall_preserves_runtime_state(self):
        self.install()
        credential = self.data_root / "existing.dpapi"
        credential.write_bytes(b"opaque-state")
        self.assertEqual(self.install()["state"], "ALREADY_INSTALLED_STATE_PRESERVED")
        self.assertEqual(credential.read_bytes(), b"opaque-state")
        self.assertEqual(self.fake.calls, ["create", "start"])

    def test_different_update_and_account_change_refused(self):
        self.install()
        with self.assertRaises(security.LocalError):
            self.engine.install(self.archive, candidate="local-service", accept_development=True)
        self.make_payload({"new.dll": b"different"})
        with self.assertRaises(security.LocalError): self.install()
        self.assertTrue(self.install_root.exists())

    def test_failed_start_rolls_back_only_created_roots(self):
        unrelated = self.root / "program" / "user-file.txt"
        unrelated.write_text("keep")
        self.fake.fail_start = True
        with self.assertRaises(security.LocalError): self.install()
        self.assertFalse(self.install_root.exists()); self.assertFalse(self.data_root.exists())
        self.assertEqual(unrelated.read_text(), "keep")
        self.assertEqual(self.fake.calls, ["create", "start", "stop", "delete"])

    def test_failed_acl_rolls_back_without_service(self):
        self.engine.acl = Mock(side_effect=OSError("test"))
        with self.assertRaises(OSError): self.install()
        self.assertFalse(self.install_root.exists()); self.assertFalse(self.data_root.exists())
        self.assertEqual(self.fake.calls, [])

    def test_stop_failure_during_rollback_preserves_created_files(self):
        self.fake.fail_start = True
        self.fake.stop = Mock(side_effect=security.LocalError("STOP_FAILED"))
        with self.assertRaises(security.LocalError): self.install()
        self.assertTrue(self.install_root.exists())
        self.assertTrue(self.data_root.exists())
        self.assertNotIn("delete", self.fake.calls)

    def test_unknown_existing_directory_preserved(self):
        self.install_root.mkdir()
        file = self.install_root / "user-file"
        file.write_text("keep")
        with self.assertRaises(security.LocalError): self.install()
        self.assertEqual(file.read_text(), "keep")

    def test_zip_escape_and_digest_tamper_refused(self):
        self.make_payload({"../outside": b"bad"})
        with self.assertRaises(security.LocalError): self.install()
        self.make_payload()
        with zipfile.ZipFile(self.archive, "a") as archive: archive.writestr("unexpected", b"bad")
        with self.assertRaises(security.LocalError): self.install()
        self.assertFalse(self.install_root.exists())

    def test_uninstall_keeps_state_and_central_registration(self):
        self.install()
        state = self.data_root / "credential.dpapi"
        state.write_bytes(b"keep-opaque")
        result = self.engine.uninstall()
        self.assertFalse(self.install_root.exists())
        self.assertEqual(state.read_bytes(), b"keep-opaque")
        self.assertEqual(result["central_revocation"], "NOT_REQUESTED")

    def test_uninstall_foreign_file_refused(self):
        self.install()
        (self.install_root / "user-data").write_text("keep")
        with self.assertRaises(security.LocalError): self.engine.uninstall()
        self.assertTrue(self.install_root.exists()); self.assertNotIn("delete", self.fake.calls)

    def test_uninstall_unknown_empty_directory_is_not_deleted(self):
        self.install()
        (self.install_root / "user-folder").mkdir()
        with self.assertRaises(security.LocalError): self.engine.uninstall()
        self.assertTrue((self.install_root / "user-folder").exists())

    def test_removal_scope_rejected(self):
        with self.assertRaises(security.LocalError): installer.remove_created_tree(self.root, self.root)

    def test_dpapi_probe_reuses_same_ciphertext_and_reloads(self):
        folder = self.root / "probe"
        acl = lambda *a, **k: None
        first = preflight.probe_store(folder, SID, protector=Protector(), acl=acl)
        second = preflight.probe_store(folder, SID, protector=Protector(), acl=acl)
        self.assertEqual(first, second)
        self.assertNotIn(b"OSGuard-development-probe-v1:", (folder / "dpapi-probe.dpapi").read_bytes())

    def test_dpapi_wrong_account_no_fallback(self):
        folder = self.root / "probe"
        preflight.probe_store(folder, SID, protector=Protector(), acl=lambda *a, **k: None)
        raw = (folder / "dpapi-probe.dpapi").read_bytes()
        failed = Mock(); failed.unprotect.side_effect = OSError("wrong-account")
        with self.assertRaises(OSError): preflight.probe_store(folder, SID, protector=failed, acl=lambda *a, **k: None)
        self.assertEqual((folder / "dpapi-probe.dpapi").read_bytes(), raw)

    def test_preflight_does_not_write_for_wrong_identity(self):
        self.install()
        with patch.object(preflight, "os_observation", return_value={"supported": True}):
            result = preflight.observe(self.config, identity=lambda: "different", member=lambda sid: True, protector=Protector(), acl=lambda *a, **k: None)
        self.assertEqual(result["observations"]["dpapi"]["state"], "SKIP")
        self.assertFalse((self.data_root / "probe").exists())
        self.assertIsNone(result["ready"])

    def test_preflight_identity_dpapi_and_policy_pending(self):
        self.install()
        with patch.object(preflight, "os_observation", return_value={"supported": True}):
            result = preflight.observe(self.config, identity=lambda: SID, member=lambda sid: True, protector=Protector(), acl=lambda *a, **k: None)
        self.assertEqual(result["observations"]["dpapi"]["state"], "PASS")
        self.assertIsNone(result["ready"])
        self.assertEqual(result["observations"]["privileged_check"]["state"], "SKIP")

    def test_runtime_idle_never_opens_credentials_or_network(self):
        factory = Mock()
        runtime.run(self.config, Stop(), preflight=lambda config: self.ready(), store_factory=factory, emit=lambda *args: None)
        factory.assert_not_called()

    def test_service_stop_before_work_has_no_preflight_side_effect(self):
        stop, probe = Stop(), Mock()
        stop.set()
        runtime.run(self.config, stop, preflight=probe)
        probe.assert_not_called()

    def test_store_failure_blocks_without_network_or_credential_deletion(self):
        factory = Mock()
        runtime.run({**self.config, "transport_enabled": True}, Stop(), preflight=lambda config: self.ready(),
                    store_factory=Mock(side_effect=OSError("store unavailable")), agent_factory=factory, emit=lambda *args: None)
        factory.assert_not_called()

    def test_product_io_probe_removes_only_own_temporary_files(self):
        self.data_root.mkdir()
        (self.data_root / "user-file").write_text("keep")
        self.assertEqual(preflight.probe_paths(self.config, acl=lambda *a, **k: None)["state"], "PASS")
        self.assertEqual((self.data_root / "user-file").read_text(), "keep")
        self.assertFalse(list(self.data_root.rglob("*.tmp")))

    def test_config_cannot_enable_check_or_move_product_roots(self):
        self.install()
        path = self.install_root / "service-local.json"
        value = json.loads(path.read_text())
        for changes in ({"check_enabled": True}, {"data_root": str(self.root)}):
            path.write_text(json.dumps({**value, **changes}))
            with patch.object(runtime, "known_roots", return_value=(self.install_root, self.data_root)), self.assertRaises(security.LocalError):
                runtime.load_config(path)

    def test_preflight_tls_unconfigured_does_not_contact_central(self):
        with patch.object(preflight, "CentralTransport") as transport:
            self.assertEqual(preflight.tls_observation(None)["state"], "SKIP")
        transport.assert_not_called()

    def test_preflight_tls_preparation_never_sends_auth(self):
        path = self.root / "tls-config.json"
        path.write_text(json.dumps({"ca_file": "public.pem", "ca_sha256_fingerprint": "a" * 64,
                                    "central_server_url": "https://central.example"}))
        with patch.object(preflight, "CentralTransport") as transport, patch.object(preflight.socket, "create_connection") as connect:
            self.assertEqual(preflight.tls_observation(path)["state"], "OBSERVED")
        transport.return_value.send.assert_not_called(); connect.assert_not_called()

    def test_runtime_reconnect_preserves_outbox_and_closes_store(self):
        config = {**self.config, "transport_enabled": True}
        state, agent, stop = Mock(), Mock(), Stop(after=3)
        state.data = {"outbox": {"pending": {"message_id": "same"}}}
        agent.heartbeat.side_effect = [CentralError("NETWORK_ERROR"), CentralError("NETWORK_ERROR"), None]
        agent.heartbeat_interval = 30
        runtime.run(config, stop, preflight=lambda config: self.ready(), store_factory=lambda *a, **k: state, agent_factory=lambda *a: agent, emit=lambda *args: None)
        self.assertEqual(stop.waits, [1, 2, 30])
        self.assertEqual(state.data["outbox"]["pending"]["message_id"], "same")
        state.close.assert_called_once()
        agent.poll_once.assert_not_called(); agent.run.assert_not_called()

    def test_auth_tls_error_is_blocked_not_restart_or_retry_storm(self):
        state, agent, stop = Mock(), Mock(), Stop()
        agent.heartbeat.side_effect = CentralError("TLS_VALIDATION_FAILED")
        runtime.run({**self.config, "transport_enabled": True}, stop, preflight=lambda config: self.ready(), store_factory=lambda *a, **k: state, agent_factory=lambda *a: agent, emit=lambda *args: None)
        self.assertEqual(agent.heartbeat.call_count, 1)
        state.close.assert_called_once(); agent.enroll.assert_not_called()

    def test_service_retry_after_is_respected_and_state_preserved(self):
        state, agent, stop = Mock(), Mock(), Stop()
        agent.heartbeat.side_effect = CentralError("RATE_LIMITED", 429, "20")
        runtime.run({**self.config, "transport_enabled": True}, stop, preflight=lambda config: self.ready(), store_factory=lambda *a, **k: state,
                    agent_factory=lambda *a: agent, emit=lambda *args: None)
        self.assertEqual(stop.waits, [20])
        state.close.assert_called_once()

    def test_stop_after_heartbeat_does_not_claim_or_submit(self):
        state, agent, stop = Mock(), Mock(), Stop()
        agent.heartbeat.side_effect = stop.set
        runtime.run({**self.config, "transport_enabled": True}, stop, preflight=lambda config: self.ready(), store_factory=lambda *a, **k: state, agent_factory=lambda *a: agent, emit=lambda *args: None)
        agent.send_inventory.assert_not_called(); agent.poll_once.assert_not_called()
        state.close.assert_called_once()

    def test_blocked_checker_cannot_execute_any_code(self):
        for code in ("W-47", "W-62", "HARDEN"):
            with self.assertRaises(security.LocalError): runtime.blocked_checker(code)

    def test_credential_migration_path_rejected_before_network(self):
        path = self.root / "central.json"
        path.write_text(json.dumps({"state_dir": "administrator-state"}))
        config = {**self.config, "central_config": str(path)}
        with patch.object(runtime, "CentralTransport") as transport, self.assertRaises(security.LocalError):
            runtime.online_agent(config, Mock())
        transport.assert_not_called()

    def test_scm_dispatch_stop_state_transitions(self):
        class Function:
            def __init__(self, body): self.body = body
            def __call__(self, *args): return self.body(*args)
        api = Mock()
        states, handlers = [], []
        api.RegisterServiceCtrlHandlerExW = Function(lambda name, handler, ctx: handlers.append(handler) or 1)
        api.SetServiceStatus = Function(lambda handle, value: states.append(ctypes.cast(value, ctypes.POINTER(scm.Status)).contents.state) or 1)
        api.StartServiceCtrlDispatcherW = Function(lambda entries: entries[0].main(0, None) or 1)
        def worker(stop):
            self.assertFalse(stop.is_set())
            handlers[0](1, 0, None, None)
            self.assertTrue(stop.is_set())
        with patch.object(ctypes, "WinDLL", return_value=api): scm.dispatch(worker)
        self.assertEqual(states, [2, 4, 3, 1])

    def test_scm_auto_start_sid_privileges_and_bounded_recovery(self):
        from ctypes import wintypes as W
        class Function:
            def __init__(self, body): self.body = body
            def __call__(self, *args): return self.body(*args)
        api, changes = Mock(), {}
        api.OpenSCManagerW = Function(lambda *args: 1)
        created = []
        api.CreateServiceW = Function(lambda *args: created.append(args) or 2)
        def changed(handle, key, pointer):
            if key == 2:
                value = ctypes.cast(pointer, ctypes.POINTER(scm.FailureActions)).contents
                changes[key] = [(value.actions[i].kind, value.actions[i].delay) for i in range(value.count)]
            elif key == 6:
                value = ctypes.cast(pointer, ctypes.POINTER(W.LPWSTR)).contents.value
                changes[key] = value
            return 1
        api.ChangeServiceConfig2W = Function(changed)
        api.CloseServiceHandle = Function(lambda handle: 1)
        with patch.object(ctypes, "WinDLL", return_value=api):
            native = scm.NativeSCM()
            native.create('"fixed.exe" --scm', "NT SERVICE\\" + SERVICE_NAME)
        self.assertEqual(created[0][5], 2)
        self.assertEqual(changes[2], [(1, 30000), (1, 120000), (0, 0)])
        self.assertEqual(changes[6], "SeChangeNotifyPrivilege")
