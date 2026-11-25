"""서비스 수명 관리. 현재 network 권한은 기존 HB/Inventory에 한정, Claim은 닫혀 있다."""

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re

from ..central.contract import Manifest
from ..central.storage import ProtectedState, reject_reparse
from ..central.transport import CentralError, CentralTransport
from ..central.service import CentralAgent
from . import MANIFEST_NAME
from .preflight import observe
from .security import LocalError, product_acl, candidate_account, known_roots


def load_config(path):
    path = Path(path).absolute()
    reject_reparse(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"format", "candidate", "service_sid", "account_sid", "install_root", "data_root", "manifest_path", "transport_enabled", "central_config"}
    if set(value) != allowed or value["format"] != 1 or type(value["transport_enabled"]) is not bool:
        raise LocalError("LOCAL_SERVICE_CONFIG_INVALID")
    candidate_account(value["candidate"])
    if Path(value["install_root"]).resolve() != path.parent.resolve(): raise LocalError("INSTALL_ROOT_MISMATCH")
    root, data = known_roots()
    if Path(value["install_root"]).absolute() != root.absolute() or Path(value["data_root"]).absolute() != data.absolute():
        raise LocalError("PRODUCT_ROOT_MISMATCH")
    for key in ("install_root", "data_root", "manifest_path"):
        if not Path(value[key]).is_absolute(): raise LocalError("ABSOLUTE_PRODUCT_PATH_REQUIRED")
        reject_reparse(value[key])
    if not Path(value["manifest_path"]).resolve().is_relative_to(path.parent.resolve()):
        raise LocalError("MANIFEST_OUTSIDE_PRODUCT")
    if value["central_config"]:
        central = Path(value["central_config"])
        if not central.is_absolute() or not central.resolve().is_relative_to(path.parent.resolve()):
            raise LocalError("CENTRAL_CONFIG_OUTSIDE_PROTECTED_PRODUCT")
        reject_reparse(central)
    return value


def write_observation(config, payload):
    directory = Path(config["data_root"]) / "logs"
    reject_reparse(directory)
    directory.mkdir(parents=True, exist_ok=True)
    product_acl(directory, config["service_sid"], writable=True)
    target = directory / "service-status.json"
    temp = directory / "service-status.tmp"
    reject_reparse(target)
    reject_reparse(temp)
    # 로컬 probe의 제한된 관측만 저장하며 Credential/예외 원문은 기록하지 않는다.
    payload = {"observed_at": datetime.now(timezone.utc).isoformat(), **payload}
    with temp.open("w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    product_acl(temp, config["service_sid"], writable=True)
    os.replace(temp, target)


def blocked_checker(*args, **kwargs):
    raise LocalError("SERVICE_CHECK_AND_HARDEN_DISABLED")


def online_agent(config, state):
    if not config["central_config"]: raise LocalError("CENTRAL_CONFIG_NOT_PROVISIONED")
    file = Path(config["central_config"])
    reject_reparse(file)
    central = json.loads(file.read_text(encoding="utf-8"))
    runtime_path = (Path(config["data_root"]) / "runtime").resolve()
    configured_path = Path(central["state_dir"])
    if not configured_path.is_absolute(): configured_path = file.parent / configured_path
    if configured_path.resolve() != runtime_path: raise LocalError("NO_ADMINISTRATOR_STATE_MIGRATION")
    def local(value):
        path = Path(value)
        return path if path.is_absolute() else file.parent / path
    transport = CentralTransport(central["central_server_url"], ca_file=local(central["ca_file"]),
                                 ca_fingerprint=central["ca_sha256_fingerprint"], timeout=10)
    manifest = Manifest(json.loads(Path(config["manifest_path"]).read_text(encoding="utf-8")))
    agent = CentralAgent(transport, state, manifest, checker=blocked_checker, retries=0)
    receipt = state.data.get("enrollment_receipt") or {}
    if (not state.data["credential"] or receipt.get("central_server_url") != transport.base_url
            or receipt.get("server_id") != agent.credential["server_id"]):
        raise LocalError("SERVICE_CREDENTIAL_NOT_PROVISIONED")
    return agent


def run(config, stop, *, preflight=observe, store_factory=ProtectedState, agent_factory=online_agent, emit=write_observation):
    if stop.is_set(): return
    report = preflight(config)
    emit(config, report)
    # 계정/무결성/DPAPI 검증 실패는 서비스 재시작으로 고치지 않는다. 로컬 BLOCKED 상태로 유지.
    observations = report["observations"]
    usable = (observations.get("identity", {}).get("state") == "PASS"
              and observations.get("dpapi", {}).get("state") == "PASS"
              and observations.get("os", {}).get("supported") is True
              and observations.get("manifest", {}).get("items") == 64
              and observations.get("integrity", {}).get("checksum_match") is True
              and observations.get("product_io", {}).get("state") == "PASS"
              and observations.get("service", {}).get("state") == "OBSERVED")
    if not usable or not config["transport_enabled"]:
        while not stop.wait(30): pass
        return
    state = None
    delay = 1
    try:
        state = store_factory(Path(config["data_root"]) / "runtime",
                              acl=lambda path: product_acl(path, config["service_sid"], writable=True))
        agent = agent_factory(config, state)
        while not stop.is_set():
            try:
                agent.heartbeat()
                if stop.is_set(): break
                agent.send_inventory()
                emit(config, {"transport": "ACK_OBSERVED", "check_enabled": False, "ready": None})
                delay = 1
                stop.wait(agent.heartbeat_interval)
            except CentralError as exc:
                temporary = exc.code == "NETWORK_ERROR" or exc.status == 429 or 500 <= exc.status < 600
                emit(config, {"transport": "RETRY_WAIT" if temporary else "AUTH_OR_TLS_BLOCKED", "code": exc.code, "ready": None})
                if not temporary:
                    while not stop.wait(30): pass
                    break
                if exc.retry_after is not None:
                    try:
                        retry_after = float(exc.retry_after)
                    except (TypeError, ValueError):
                        from email.utils import parsedate_to_datetime
                        retry_after = (parsedate_to_datetime(exc.retry_after) - datetime.now(timezone.utc)).total_seconds()
                    if not math.isfinite(retry_after) or retry_after < 0 or retry_after > 300:
                        raise LocalError("INVALID_RETRY_AFTER")
                    delay = max(delay, retry_after)
                stop.wait(delay)
                delay = min(delay * 2, 60)
    except Exception as exc:
        code = str(exc) if isinstance(exc, LocalError) and re.fullmatch(r"[A-Z0-9_]+", str(exc)) else "SERVICE_RUNTIME_BLOCKED"
        emit(config, {"code": code, "ready": None})
        while not stop.wait(30): pass
    finally:
        if state is not None: state.close()  # credential/outbox/진행 attempt를 삭제하거나 재태깅하지 않는다.
