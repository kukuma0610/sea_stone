"""로컬 관측만. 승인 catalog/READY 판정·Central 보고·Enrollment는 수행하지 않는다."""

import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import sys
import tempfile

from ..central.contract import Manifest
from ..central.storage import DPAPI, reject_reparse
from ..central.transport import CentralTransport
from .security import LocalError, token_user, is_member, product_acl, privilege_observation
from . import MANIFEST_NAME


def os_observation():
    if os.name != "nt": return {"supported": False, "platform": "non-windows"}
    info = sys.getwindowsversion()
    base = info.build == 20348 and info.product_type == 3 and platform.machine() == "AMD64"
    domain = None
    if base:
        from ..checks.common import NativeWindowsReadOnlyApi
        domain = NativeWindowsReadOnlyApi().domain_joined()
    return {"supported": base and domain is False, "domain_joined": domain,
            "build": info.build, "product_type": info.product_type, "architecture": platform.machine()}


def integrity(root):
    root = Path(root).absolute()
    reject_reparse(root)
    index_path = root / "payload-manifest.json"
    reject_reparse(index_path)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("development_unsigned") is not True or not isinstance(index.get("files"), dict) or not index["files"]:
        raise LocalError("DEVELOPMENT_PAYLOAD_INDEX_INVALID")
    for name, digest in index["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or ":" in name or "\\" in name:
            raise LocalError("PAYLOAD_PATH_INVALID")
        path = root / relative
        reject_reparse(path)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise LocalError("PAYLOAD_DIGEST_MISMATCH")
    if "os-guard-agent-service.exe" not in index["files"]:
        raise LocalError("SERVICE_BINARY_MISSING")
    return {"checksum_match": True, "publisher_signature_verified": False, "commercial_approved": False}


def probe_store(directory, sid, *, protector=None, acl=product_acl):
    """기존 probe ciphertext를 유지하므로 실제 계정의 재시작/재부팅 비교가 가능하다."""
    directory = Path(directory)
    reject_reparse(directory)
    directory.mkdir(parents=True, exist_ok=True)
    acl(directory, sid, writable=True)
    path = directory / "dpapi-probe.dpapi"
    reject_reparse(path)
    protector = protector or DPAPI()
    if not path.exists():
        raw = protector.protect(b"OSGuard-development-probe-v1:" + os.urandom(32))
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        acl(path, sid, writable=True)
    protected = path.read_bytes()
    raw = protector.unprotect(protected)
    if not raw.startswith(b"OSGuard-development-probe-v1:") or len(raw) != len(b"OSGuard-development-probe-v1:") + 32:
        raise LocalError("DPAPI_PROBE_RELOAD_FAILED")
    return {"store_reload": True, "existing_probe_sha256": hashlib.sha256(protected).hexdigest()}


def probe_paths(config, acl=product_acl):
    for name in ("logs", "runtime", "probe"):
        directory = Path(config["data_root"]) / name
        reject_reparse(directory)
        directory.mkdir(parents=True, exist_ok=True)
        acl(directory, config["service_sid"], writable=True)
        fd, temporary = tempfile.mkstemp(prefix="osguard-preflight-", suffix=".tmp", dir=directory)
        target = Path(temporary + ".replaced")
        try:
            os.write(fd, b"product-io-probe")
            os.fsync(fd)
            os.close(fd)
            fd = None
            acl(Path(temporary), config["service_sid"], writable=True)
            os.replace(temporary, target)
            if target.read_bytes() != b"product-io-probe": raise LocalError("PRODUCT_IO_PROBE_FAILED")
        finally:
            if fd is not None: os.close(fd)
            for path in (Path(temporary), target):
                if path.exists(): path.unlink()
    return {"state": "PASS", "code": "PRODUCT_PATH_ATOMIC_IO_VERIFIED"}


def service_observation(config):
    from .scm import NativeSCM
    from .installer import binary_command
    from .security import candidate_account
    service = NativeSCM().query()
    if service is None: return {"state": "FAIL", "code": "SCM_SERVICE_MISSING"}
    if (service["binary"] != binary_command(config["install_root"])
            or service["account"].casefold() != candidate_account(config["candidate"]).casefold()
            or service["start"] != 2):
        return {"state": "FAIL", "code": "SCM_SERVICE_BINDING_MISMATCH"}
    return {"state": "OBSERVED", "scm_state": service["state"], "automatic_start": True}


def tls_observation(config_path, *, connect=False):
    if not config_path: return {"state": "SKIP", "code": "CENTRAL_CONFIG_NOT_PROVISIONED"}
    path = Path(config_path)
    reject_reparse(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    ca = Path(value["ca_file"])
    if not ca.is_absolute(): ca = path.parent / ca
    transport = CentralTransport(value["central_server_url"], ca_file=ca,
                                 ca_fingerprint=value["ca_sha256_fingerprint"], timeout=5)
    if not connect:
        return {"state": "OBSERVED", "code": "TLS_CONTEXT_PREPARED_HANDSHAKE_NOT_TESTED"}
    from urllib.parse import urlsplit
    url = urlsplit(transport.base_url)
    context = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection((url.hostname, url.port or 443), timeout=5) as stream:
        with context.wrap_socket(stream, server_hostname=url.hostname):
            return {"state": "PASS", "code": "TLS_HANDSHAKE_VERIFIED_NO_AUTH_SENT"}


def observe(config, *, identity=token_user, member=is_member, protector=None, acl=product_acl, connect=False):
    result = {"policy_state": "LOCAL_ONLY_POLICY_UNAPPROVED", "ready": None, "observations": {}}
    observations = result["observations"]
    for name, probe in (
        ("os", os_observation),
        ("manifest", lambda: {"items": len(Manifest(json.loads(Path(config["manifest_path"]).read_text(encoding="utf-8"))).items)}),
        ("integrity", lambda: integrity(config["install_root"])),
        ("service", lambda: service_observation(config)),
        ("privileges", lambda: {"state": "OBSERVED", "values": privilege_observation()}),
    ):
        try: observations[name] = {"state": "OBSERVED", **probe()}
        except Exception: observations[name] = {"state": "FAIL", "code": name.upper() + "_PROBE_FAILED"}
    verified = False
    try:
        actual = identity()
        verified = actual == config["account_sid"] and member(config["service_sid"])
        observations["identity"] = {"state": "PASS" if verified else "FAIL", "code": "RUNTIME_IDENTITY_MATCH" if verified else "SERVICE_IDENTITY_MISMATCH"}
    except Exception:
        observations["identity"] = {"state": "FAIL", "code": "SERVICE_IDENTITY_QUERY_FAILED"}
    if verified:
        try:
            observations["product_io"] = probe_paths(config, acl=acl)
            probe = probe_store(Path(config["data_root"]) / "probe", config["service_sid"], protector=protector, acl=acl)
            observations["dpapi"] = {"state": "PASS", **probe}
        except Exception:
            observations["dpapi"] = {"state": "FAIL", "code": "DPAPI_SERVICE_ACCOUNT_PROBE_FAILED"}
    else:
        observations["dpapi"] = {"state": "SKIP", "code": "NO_CROSS_ACCOUNT_FALLBACK"}
    try:
        observations["tls"] = tls_observation(config.get("central_config"), connect=connect)
    except Exception:
        observations["tls"] = {"state": "FAIL", "code": "TLS_PREPARATION_FAILED"}
    observations["privileged_check"] = {"state": "SKIP", "code": "SIGNED_TICKET_POLICY_NOT_APPROVED"}
    observations["enrollment"] = {"state": "SKIP", "code": "AUTOMATIC_ENROLLMENT_DISABLED"}
    return result
