"""외부 책임자 CMS 분리서명 검증만 제공한다. 키/인증서/서명을 생성하지 않는다."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from scripts import lab_hardening_policy as policy


def payload(data):
    # 책임자가 서명할 원문: 경로·승인서 해시·전체 VM/commit/code/시각/위험 승인 범위.
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


VERIFY = r"""
$ErrorActionPreference='Stop'
try {
 $stage='CMS_INIT'
 Add-Type -AssemblyName System.Security
 $a=[Console]::In.ReadToEnd() | ConvertFrom-Json
 $stage='CERTIFICATE_FORMAT'
 $certBytes=[Convert]::FromBase64String($a.certificate)
 if ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($certBytes) -ne [Security.Cryptography.X509Certificates.X509ContentType]::Cert) { throw 'PUBLIC_CERT_ONLY' }
 $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$certBytes)
 $sha=[Security.Cryptography.SHA256]::Create()
 $fingerprint=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()
 $stage='CERTIFICATE_PIN'
 if ($fingerprint -cne $a.pin) { throw 'PIN' }
 if ($cert.HasPrivateKey) { throw 'PUBLIC_ONLY' }
 $stage='CERTIFICATE_VALIDITY'
 if ([DateTime]::UtcNow -lt $cert.NotBefore.ToUniversalTime() -or [DateTime]::UtcNow -gt $cert.NotAfter.ToUniversalTime()) { throw 'VALIDITY' }
 $usage=@($cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.15'})
 $stage='CERTIFICATE_USAGE'
 if ($usage.Count -ne 1 -or ($usage[0].KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) { throw 'KEY_USAGE' }
 $content=New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,[Convert]::FromBase64String($a.payload))
 $cms=New-Object Security.Cryptography.Pkcs.SignedCms -ArgumentList $content,$true
 $stage='SIGNATURE_SHAPE'
 $cms.Decode([Convert]::FromBase64String($a.signature))
 if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1) { throw 'DETACHED_SINGLE_SIGNER_REQUIRED' }
 $signer=$cms.SignerInfos[0]
 if ($signer.CounterSignerInfos.Count -ne 0 -or $signer.DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'SHA256_ONLY' }
 $signerPin=([BitConverter]::ToString($sha.ComputeHash($signer.Certificate.RawData))).Replace('-','').ToLowerInvariant()
 $stage='SIGNER_PIN'
 if ($signerPin -cne $a.pin) { throw 'SIGNER' }
 # CheckSignature(true) 자체는 신뢰 확인이 아니다. 별도 확인된 직접 pin을 위에서 검증한다.
 # 체인/신뢰 저장소는 수정하지 않으며 폐기 여부는 이 오프라인 pin 정책으로 자동 확인하지 않는다.
 $stage='CMS_CRYPTO_VERIFY'
 $cms.CheckSignature($true)
 [pscustomobject]@{verified=$true} | ConvertTo-Json -Compress
} catch {
 [pscustomobject]@{verified=$false; stage=$stage} | ConvertTo-Json -Compress
}
"""


def read_bytes(path, limit):
    policy.reject_reparse(path)
    policy.require(path.is_file() and path.stat().st_size <= limit, "OWNER_EVIDENCE_FILE_INVALID")
    return path.read_bytes()


def verify_cms(content, signature, certificate, pin):
    request = {"payload": base64.b64encode(content).decode(),
               "signature": base64.b64encode(signature).decode(),
               "certificate": base64.b64encode(certificate).decode(), "pin": pin}
    # 명령은 고정이며 문서·서명·경로는 command line이나 로그에 넣지 않는다.
    executable = Path(policy.e2e.system_executable("gpresult.exe")).parent / "WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", VERIFY],
                            input=json.dumps(request).encode("ascii"), capture_output=True, timeout=30,
                            shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    policy.require(result.returncode == 0, "OWNER_SIGNATURE_QUERY_FAILED")
    try:
        response = json.loads(result.stdout.decode("utf-8-sig"))
    except (UnicodeError, ValueError):
        raise policy.LabRejected("OWNER_SIGNATURE_RESPONSE_INVALID") from None
    if not isinstance(response, dict) or response.get("verified") is not True:
        stage = response.get("stage") if isinstance(response, dict) else None
        allowed = {"CMS_INIT", "CERTIFICATE_FORMAT", "CERTIFICATE_PIN", "CERTIFICATE_VALIDITY", "CERTIFICATE_USAGE",
                   "SIGNATURE_SHAPE", "SIGNER_PIN", "CMS_CRYPTO_VERIFY"}
        raise policy.LabRejected("OWNER_"+stage+"_FAILED" if stage in allowed else "OWNER_SIGNATURE_INVALID")


def verify_owner(data, owner, proof):
    prefix = "approvers.TEST_OWNER"
    try:
        policy.require(isinstance(proof, dict) and set(proof) == {"approval_file", "certificate_file", "certificate_sha256"},
                       "INDEPENDENT_OWNER_CERTIFICATE_REQUIRED")
        pin = proof["certificate_sha256"]
        policy.require(isinstance(pin, str) and re.fullmatch(r"[0-9a-fA-F]{64}", pin), "OWNER_CERTIFICATE_PIN_INVALID")
        policy.require(isinstance(owner["document_sha256"], str) and
                       re.fullmatch(r"[0-9a-fA-F]{64}", owner["document_sha256"]), "OWNER_DOCUMENT_HASH_INVALID")
        base = Path(proof["approval_file"]).absolute().parent
        def local(name):
            policy.require(isinstance(owner[name], str) and bool(owner[name].strip()), "OWNER_EVIDENCE_PATH_REQUIRED")
            path = Path(owner[name])
            return path if path.is_absolute() else base / path
        def evidence(field, path, limit):
            try:
                return read_bytes(path, limit)
            except Exception:
                raise policy.ApprovalFieldsRejected([(prefix+"."+field, "EVIDENCE_FILE_UNREADABLE_OR_INVALID")]) from None
        document = evidence("document_file", local("document_file"), 16*1024*1024)
        policy.require(hashlib.sha256(document).hexdigest() == owner["document_sha256"].lower(), "OWNER_DOCUMENT_HASH_MISMATCH")
        certificate = evidence("certificate", Path(proof["certificate_file"]), 65536)
        signature = evidence("signature_file", local("signature_file"), 1024*1024)
        verify_cms(payload(data), signature, certificate, pin.lower())
    except policy.ApprovalFieldsRejected:
        raise
    except Exception as exc:
        reason = str(exc) if isinstance(exc, policy.LabRejected) else "OWNER_EVIDENCE_UNREADABLE_OR_INVALID"
        field = (".document_sha256" if "DOCUMENT_HASH" in reason else
                 ".certificate" if "CERTIFICATE" in reason or "SIGNER_PIN" in reason else ".signature_file")
        raise policy.ApprovalFieldsRejected([(prefix+field, reason)]) from None
