from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import lab_hardening_policy as policy, lab_hardening_e2e as lab, lab_owner_signature as signer
from tests import test_lab_hardening as fixtures


class ApprovalDiagnosticTests(unittest.TestCase):
    def test_uuid_time_sid_errors_are_aggregated_without_values(self):
        value = fixtures.record()
        value["approval_id"] = "sensitive-uuid-value"
        value["issued_at"] = "sensitive-date-value"
        value["approvers"][1]["sid"] = "sensitive-person-value"
        with self.assertRaises(policy.ApprovalFieldsRejected) as caught:
            policy.validate_approval(value, code="W-07", vm=fixtures.VM, commit=fixtures.COMMIT, now=fixtures.NOW)
        self.assertIn(("approval_id", "UUID_REQUIRED"), caught.exception.issues)
        self.assertIn(("issued_at", "ISO8601_WITH_TIMEZONE_REQUIRED"), caught.exception.issues)
        self.assertTrue(any(field == "approvers[1].sid" for field, _ in caught.exception.issues))
        self.assertNotIn("sensitive", str(caught.exception.issues))

    def test_cli_prints_fields_before_vm_queries_and_never_executes(self):
        value = fixtures.record()
        value["approval_id"] = "private-token-placeholder"
        output = io.StringIO()
        with patch.object(lab.e2e, "_is_administrator", return_value=True), patch.object(lab, "load_record", return_value=value), \
                patch.object(policy, "identity") as identity, patch.object(lab, "run") as run, redirect_stdout(output):
            self.assertEqual(lab.main(["--code", "W-07", "--approval-file", "mock.json", "--execute"]), 1)
            identity.assert_not_called()
            run.assert_not_called()
        self.assertIn("field=approval_id reason=UUID_REQUIRED", output.getvalue())
        self.assertNotIn("private-token-placeholder", output.getvalue())

    def test_expired_record_is_identified_without_mutating_dates(self):
        value = fixtures.record()
        value["expires_at"] = fixtures.NOW.isoformat()
        before = deepcopy(value)
        with self.assertRaises(policy.ApprovalFieldsRejected) as caught:
            policy.validate_approval(value, code="W-07", vm=fixtures.VM, commit=fixtures.COMMIT, now=fixtures.NOW)
        self.assertEqual(caught.exception.issues, [("issued_at/expires_at", "APPROVAL_EXPIRED_OR_INVALID")])
        self.assertEqual(value, before)

    def test_export_is_unsigned_only_and_cannot_execute_or_overwrite(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)/"unsigned.bin"
            with patch.object(lab.e2e, "_is_administrator", return_value=True), patch.object(lab, "load_record", return_value=fixtures.record()), \
                    patch.object(lab, "run") as run, patch.object(policy, "environment") as environment, redirect_stdout(io.StringIO()):
                args = ["--code", "W-07", "--approval-file", "mock.json", "--export-approval-payload", str(output)]
                self.assertEqual(lab.main(args), 0)
                self.assertEqual(output.read_bytes(), signer.payload(fixtures.record()))
                self.assertEqual(lab.main(args), 1)
                self.assertEqual(lab.main(args+["--execute"]), 1)
                run.assert_not_called()
                environment.assert_not_called()


class ExternalOwnerTests(unittest.TestCase):
    def prepare(self, folder):
        document = folder/"owner-approval.pdf"
        document.write_bytes(b"mock document, not an actual risk approval")
        (folder/"owner.p7s").write_bytes(b"invalid mock signature bytes")
        (folder/"owner.cer").write_bytes(b"mock public certificate bytes")
        value = fixtures.record()
        value["approvers"][1] = {"role": "TEST_OWNER", "method": "DETACHED_CMS_SHA256", "accepted": True,
             "approved_at": fixtures.NOW.isoformat(), "reference": "mock-owner-approval-reference",
             "document_file": document.name, "document_sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
             "signature_file": "owner.p7s"}
        proof = {"approval_file": folder/"approval.json", "certificate_file": folder/"owner.cer", "certificate_sha256": "a"*64}
        return value, proof

    def validate(self, value, proof):
        return policy.validate_approval(value, code="W-07", vm=fixtures.VM, commit=fixtures.COMMIT,
                                        now=fixtures.NOW, external_proof=proof)

    def test_external_owner_without_sid_requires_independent_pin_and_real_verifier(self):
        with TemporaryDirectory() as temp:
            value, proof = self.prepare(Path(temp))
            with self.assertRaises(policy.ApprovalFieldsRejected): self.validate(value, None)
            with patch.object(signer, "verify_cms") as verify:
                self.assertEqual(len(self.validate(value, proof)), 64)
                self.assertEqual(verify.call_args.args[0], signer.payload(value))
                self.assertEqual(verify.call_args.args[3], "a"*64)
                self.assertNotIn("sid", value["approvers"][1])

    def test_document_tamper_and_missing_signature_are_blocked(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            value, proof = self.prepare(folder)
            (folder/"owner-approval.pdf").write_bytes(b"tampered")
            with patch.object(signer, "verify_cms") as verify, self.assertRaises(policy.ApprovalFieldsRejected):
                self.validate(value, proof)
            verify.assert_not_called()
            value, proof = self.prepare(folder)
            (folder/"owner.p7s").unlink()
            with self.assertRaises(policy.ApprovalFieldsRejected): self.validate(value, proof)

    def test_canonical_scope_changes_require_different_signed_content(self):
        with TemporaryDirectory() as temp:
            value, proof = self.prepare(Path(temp))
            expected = signer.payload(value)
            def cryptographic_boundary(content, *args):
                policy.require(content == expected, "OWNER_SIGNATURE_INVALID")
            for field, changed in (("approval_id", "33333333-3333-3333-3333-333333333333"),
                                   ("snapshot", {"id": "other", "confirmed": True, "recovery_procedure": "restore"})):
                changed_value = deepcopy(value)
                changed_value[field] = changed
                with patch.object(signer, "verify_cms", side_effect=cryptographic_boundary), \
                        self.subTest(field=field), self.assertRaises(policy.ApprovalFieldsRejected):
                    self.validate(changed_value, proof)

    def test_cms_boundary_is_fixed_command_and_uses_stdin_not_args(self):
        fake = SimpleNamespace(returncode=0, stdout=b'{"verified":true}')
        with patch.object(policy.e2e, "system_executable", return_value="C:/Windows/System32/gpresult.exe"), \
                patch.object(signer.subprocess, "run", return_value=fake) as run:
            signer.verify_cms(b"sensitive-content", b"sig", b"cert", "a"*64)
            argv = run.call_args.args[0]
            self.assertNotIn("sensitive-content", str(argv))
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertIn("input", run.call_args.kwargs)
            self.assertIn("$cms.CheckSignature($true)", argv[-1])
            self.assertNotIn("ComputeSignature", argv[-1])
            self.assertIn("CERTIFICATE_PIN", argv[-1])
            fake.stdout = b'{"verified":false,"stage":"CERTIFICATE_VALIDITY"}'
            with self.assertRaises(policy.LabRejected) as caught: signer.verify_cms(b"x", b"y", b"z", "a"*64)
            self.assertEqual(str(caught.exception), "OWNER_CERTIFICATE_VALIDITY_FAILED")
            fake.stdout = b'{"verified":"true"}'
            with self.assertRaises(policy.LabRejected): signer.verify_cms(b"x", b"y", b"z", "a"*64)
