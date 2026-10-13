"""검증 TLS·리다이렉트 금지·상태별 JSON/multipart 수송."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPSHandler, HTTPRedirectHandler, build_opener
import json
import math
import ctypes
from ctypes import wintypes

from .contract import ContractError, canonical


class CentralError(RuntimeError):
    def __init__(self, code, status=0, retry_after=None):
        self.code, self.status, self.retry_after = code, status, retry_after
        super().__init__(f"Central request failed: {code} ({status})")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CentralError("REDIRECT_FORBIDDEN", code)


def normalize_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path.rstrip("/") not in {"", "/agent-api/v2"}):
        raise ContractError("HTTPS Central origin or v2 base URL is required")
    return f"https://{parsed.netloc}/agent-api/v2"


def verify_ca(path, fingerprint):
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise ContractError("trusted DER SHA256 fingerprint is required")
    raw = Path(path).read_bytes()
    if b"PRIVATE KEY" in raw:
        raise ContractError("CA input must be a public certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ContractError("a single public PEM CA certificate is required") from None
    if raw.count(b"BEGIN CERTIFICATE") != 1 or hashlib.sha256(der).hexdigest() != fingerprint:
        raise ContractError("CA fingerprint mismatch")
    return der


def trust_current_user_ca(path, fingerprint):
    """명시적 CLI 요청에서만 검증된 공개 CA를 현재 사용자 ROOT에 추가한다."""
    der = verify_ca(path, fingerprint)
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CertOpenSystemStoreW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    crypt.CertOpenSystemStoreW.restype = ctypes.c_void_p
    crypt.CertAddEncodedCertificateToStore.argtypes = [ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    crypt.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
    crypt.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    crypt.CertCloseStore.restype = wintypes.BOOL
    store = crypt.CertOpenSystemStoreW(None, "ROOT")
    if not store: raise ContractError("current-user certificate store is unavailable")
    try:
        buffer = ctypes.create_string_buffer(der)
        if not crypt.CertAddEncodedCertificateToStore(store, 0x10001, buffer, len(der), 2, None):
            raise ContractError("verified CA could not be installed")
    finally:
        crypt.CertCloseStore(store, 0)


def require_installed_ca(der):
    try:
        certificates = ssl.enum_certificates("ROOT")
    except (AttributeError, OSError):
        raise ContractError("Windows ROOT trust could not be verified") from None
    for certificate, encoding, trust in certificates:
        if (encoding == "x509_asn" and certificate == der
                and (trust is True or isinstance(trust, set) and "1.3.6.1.5.5.7.3.1" in trust)):
            return
    raise ContractError("verified public CA must be installed in Windows ROOT before enrollment")


@dataclass(frozen=True)
class Response:
    status: int
    body: dict | None


class CentralTransport:
    def __init__(self, base_url, *, ca_file=None, ca_fingerprint=None, timeout=10):
        self.base_url = normalize_url(base_url)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ContractError("timeout must be a finite value in (0, 60]")
        self.timeout = timeout
        if ca_file is not None:
            require_installed_ca(verify_ca(ca_file, ca_fingerprint))
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self.opener = build_opener(HTTPSHandler(context=context), NoRedirect())

    def send(self, path, payload, headers, file_bytes=None):
        if not path.startswith("/") or path.startswith("//") or ".." in path or "?" in path:
            raise ContractError("invalid Agent endpoint")
        media = "application/json"
        data = canonical(payload)
        if file_bytes is not None:
            boundary = "osguard-" + payload["message_id"]
            media = "multipart/form-data; boundary=" + boundary
            data = (f'--{boundary}\r\nContent-Disposition: form-data; name="metadata"\r\n'
                    'Content-Type: application/json\r\n\r\n').encode() + data
            data += (f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="evidence.json"\r\n'
                     'Content-Type: application/json\r\n\r\n').encode() + file_bytes
            data += f"\r\n--{boundary}--\r\n".encode()
        if len(data) > 2 * 1024 * 1024:
            raise ContractError("request exceeds Central size limit")
        request = Request(self.base_url + path, data=data,
                          headers={"Content-Type": media, "Accept": "application/json", **headers}, method="POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = response.status
                raw = response.read(2 * 1024 * 1024 + 1)
        except HTTPError as exc:
            code = "HTTP_ERROR"
            try:
                body = json.loads(exc.read(8192))
                candidate = body.get("error", {}).get("code")
                if isinstance(candidate, str) and re.fullmatch(r"[A-Z0-9_]{1,80}", candidate): code = candidate
            except Exception:
                pass
            retry = exc.headers.get("Retry-After") if exc.headers else None
            raise CentralError(code, exc.code, retry) from None
        except (ssl.SSLError, ssl.CertificateError):
            raise CentralError("TLS_VALIDATION_FAILED") from None
        except URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                raise CentralError("TLS_VALIDATION_FAILED") from None
            raise CentralError("NETWORK_ERROR") from None
        except (OSError, TimeoutError):
            raise CentralError("NETWORK_ERROR") from None
        if status == 204:
            if raw: raise ContractError("204 response must be empty")
            return Response(status, None)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise CentralError("INVALID_RESPONSE_JSON", status) from None
        if not isinstance(body, dict) or len(raw) > 2 * 1024 * 1024:
            raise CentralError("INVALID_RESPONSE_JSON", status)
        return Response(status, body)
