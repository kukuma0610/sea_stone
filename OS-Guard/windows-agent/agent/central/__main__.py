"""공식 foreground Central 연결 진입점. Service/Installer는 별도 협의한다."""

import argparse
import json
from pathlib import Path
import threading

from .contract import ContractError, Manifest
from .inventory import collect_snapshot
from .release import RegistrationRelease
from .service import CentralAgent
from .storage import ProtectedState, reject_reparse, restrict_acl
from .transport import CentralError, CentralTransport, normalize_url, trust_current_user_ca
from .. import AGENT_VERSION


def main(argv=None):
    parser = argparse.ArgumentParser(description="OS Guard Central v2 foreground Agent")
    parser.add_argument("command", choices=("enroll", "online", "run", "once", "rotate", "recover-rotation"))
    parser.add_argument("--config", required=True, type=Path, help="비밀값 없는 연결 설정 JSON")
    parser.add_argument("--registration-file", type=Path)
    parser.add_argument("--once", action="store_true", help="online 한 주기 후 종료; Claim/CHECK 없음")
    parser.add_argument("--re-enroll", action="store_true")
    parser.add_argument("--trust-ca", action="store_true", help="신뢰 전달받은 공개 CA를 현재 사용자 ROOT에 등록")
    args = parser.parse_args(argv)
    state = None
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        allowed = {"central_server_url", "manifest_file", "state_dir", "ca_file", "ca_sha256_fingerprint",
                   "timeout_sec", "retry_count", "retry_base_sec", "poll_interval_sec", "lease_renewal_fraction"}
        if not isinstance(config, dict) or set(config)-allowed:
            raise ContractError("configuration contains unsupported or secret fields")
        def local_path(key):
            path = Path(config[key])
            return path if path.is_absolute() else args.config.absolute().parent / path
        if args.once and args.command != "online":
            raise ContractError("--once is only valid for online")
        if args.command in {"enroll", "online"}:
            manifest = RegistrationRelease()
        else:
            # 배포 소스에 포함된 승인 manifest가 기본값이다. 명시 경로가 잘못되면 fallback하지 않는다.
            manifest_path = (local_path("manifest_file") if "manifest_file" in config else
                             Path(__file__).resolve().with_name("manifest-windows-64-2026-v1.json"))
            reject_reparse(manifest_path)
            manifest = Manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
        ca = local_path("ca_file") if config.get("ca_file") else None
        registration = registration_path = None
        if args.command == "enroll":
            if args.registration_file is None: raise ContractError("registration file is required")
            registration_path = args.registration_file.absolute()
            reject_reparse(registration_path)
            restrict_acl(registration_path)
            registration = json.loads(registration_path.read_text(encoding="utf-8-sig"))
            if not isinstance(registration, dict): raise ContractError("invalid registration file")
            if normalize_url(registration.get("central_server_url", "")) != normalize_url(config["central_server_url"]):
                raise ContractError("registration Central URL mismatch")
            if ca is None or registration.get("ca_sha256_fingerprint") != config.get("ca_sha256_fingerprint"):
                raise ContractError("registration CA binding mismatch")
        elif args.registration_file is not None or args.re_enroll or args.trust_ca:
            raise ContractError("registration arguments are only valid for enroll")
        if args.trust_ca:
            if ca is None: raise ContractError("public CA file is required")
            trust_current_user_ca(ca, config.get("ca_sha256_fingerprint", ""))
        transport = CentralTransport(config["central_server_url"], ca_file=ca,
                                     ca_fingerprint=config.get("ca_sha256_fingerprint"),
                                     timeout=config.get("timeout_sec", 10))
        state = ProtectedState(local_path("state_dir"))
        agent = CentralAgent(transport, state, manifest, retries=config.get("retry_count", 5),
                             retry_base=config.get("retry_base_sec", 1), poll_interval=config.get("poll_interval_sec", 10),
                             lease_renewal_fraction=config.get("lease_renewal_fraction", 1/3))
        if args.command == "enroll":
            snapshot = collect_snapshot(manifest, AGENT_VERSION)
            if snapshot["collection"]["os"]["status"] != "SUCCEEDED":
                raise ContractError("OS collection failed before enrollment")
            receipt = state.data.get("enrollment_receipt")
            resumed = (state.data["credential"] and receipt == {
                "enrollment_id": registration.get("enrollment_id"), "server_id": registration.get("server_id"),
                "central_server_url": transport.base_url}
                and state.data["credential"]["server_id"] == registration.get("server_id"))
            if not resumed or args.re_enroll:
                agent.enroll(registration, snapshot["os"], snapshot["hostname"], re_enroll=args.re_enroll)
            agent.heartbeat()
            agent.send_inventory()
            agent.heartbeat()
            # 운영 ACK까지 확인된 뒤 삭제. 실패 시 파일은 보존한다.
            registration_path.unlink()
            print("Enrollment/DPAPI/Heartbeat/Inventory ACK verified; registration file removed")
            print("Confirm ONLINE on Central; no CHECK requested")
        elif args.command == "online":
            receipt = state.data.get("enrollment_receipt") or {}
            if (receipt.get("central_server_url") != transport.base_url
                    or receipt.get("server_id") != agent.credential["server_id"]):
                raise ContractError("protected registration receipt does not match Central")
            stop = threading.Event()
            try:
                while not stop.is_set():
                    agent.heartbeat()
                    agent.send_inventory()
                    agent.heartbeat()
                    print("Heartbeat/Inventory ACK verified; no task claim")
                    if args.once: break
                    stop.wait(agent.heartbeat_interval)
            except KeyboardInterrupt:
                stop.set()
                print("Online loop stopped; protected state retained")
        elif args.command == "rotate":
            agent.rotate()
            print("New credential protected and confirmed by Central")
        elif args.command == "recover-rotation":
            result = agent.recover_rotation()
            print("Rotation recovery confirmed" if result["recovered"] else "Rotation grace is still pending")
        elif args.command == "once":
            agent.heartbeat()
            agent.send_inventory()
            result = agent.poll_once()
            print("CHECK completion ACK verified" if result["claimed"] else "No task (204)")
        else:
            stop = threading.Event()
            try:
                agent.run(stop)
            except KeyboardInterrupt:
                stop.set()
                print("Agent stopped; protected pending state retained")
        return 0
    except Exception as exc:
        # 예외 원문/응답/headers/credential을 콘솔에 출력하지 않는다.
        print(f"Agent stopped: {exc.code if isinstance(exc, CentralError) else type(exc).__name__}")
        return 1
    finally:
        if state is not None: state.close()


if __name__ == "__main__":
    raise SystemExit(main())
