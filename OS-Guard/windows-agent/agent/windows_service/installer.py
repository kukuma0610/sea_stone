"""개발용 로컬 설치 transaction. 원격 등록/CA/privileged CHECK/업데이트는 닫혀 있다."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile

from ..central.contract import Manifest
from ..central.storage import reject_reparse
from . import MANIFEST_NAME, SERVICE_NAME
from .preflight import integrity, os_observation
from .security import LocalError, candidate_account, sid_for_account, product_acl, known_roots
from ..central.release import RegistrationRelease


def validate_payload(archive):
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or len(names) > 10000: raise LocalError("PAYLOAD_INDEX_INVALID")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or ".." in path.parts or ":" in entry.filename or "\\" in entry.filename
                    or entry.is_dir() or stat.S_ISLNK(entry.external_attr >> 16)
                    or not entry.filename or entry.file_size > 300 * 1024 * 1024):
                raise LocalError("UNSAFE_PAYLOAD_ENTRY")
        if sum(entry.file_size for entry in entries) > 800 * 1024 * 1024: raise LocalError("PAYLOAD_TOO_LARGE")
        index = json.loads(bundle.read("payload-manifest.json"))
        if index.get("development_unsigned") is not True or set(names) != set(index["files"]) | {"payload-manifest.json"}:
            raise LocalError("DEVELOPMENT_PAYLOAD_INDEX_INVALID")
        if "os-guard-agent-service.exe" not in index["files"]: raise LocalError("SERVICE_BINARY_MISSING")
        for name, digest in index["files"].items():
            if hashlib.sha256(bundle.read(name)).hexdigest() != digest: raise LocalError("PAYLOAD_DIGEST_MISMATCH")
        candidates = [name for name in index["files"] if name.endswith("/agent/central/" + MANIFEST_NAME)]
        if len(candidates) != 1: raise LocalError("BUNDLED_MANIFEST_MISSING")
        manifest = Manifest(json.loads(bundle.read(candidates[0])))
        approved = RegistrationRelease()
        if (manifest.id, manifest.version) != (approved.id, approved.version):
            raise LocalError("APPROVED_MANIFEST_IDENTITY_MISMATCH")
        return index, candidates[0]


def binary_command(root):
    # SCM에는 고정 EXE와 고정 제품 config만 전달한다. 사용자 command/argv 입력 없음.
    return f'"{Path(root) / "os-guard-agent-service.exe"}" --scm --config "{Path(root) / "service-local.json"}"'


def remove_created_tree(path, expected):
    path, expected = Path(path).absolute(), Path(expected).absolute()
    reject_reparse(path)
    if path != expected or path.name != "OS Guard Development Agent": raise LocalError("REMOVAL_SCOPE_REJECTED")
    if not path.exists(): return
    for item in path.rglob("*"): reject_reparse(item)
    shutil.rmtree(path)


class LocalInstaller:
    def __init__(self, scm, *, roots=None, acl=product_acl, sid_lookup=sid_for_account, supported=None):
        self.scm = scm
        self.root, self.data = roots or known_roots()
        self.root, self.data = Path(self.root).absolute(), Path(self.data).absolute()
        if self.root == self.data or self.root.name != "OS Guard Development Agent" or self.data.name != "OS Guard Development Agent":
            raise LocalError("PRODUCT_ROOT_INVALID")
        self.acl, self.sid_lookup = acl, sid_lookup
        self.supported = supported or (lambda: os_observation()["supported"])

    def install(self, archive, *, candidate, accept_development=False):
        account = candidate_account(candidate)
        if not accept_development: raise LocalError("UNSIGNED_DEVELOPMENT_CONSENT_REQUIRED")
        if not self.supported(): raise LocalError("SERVER_2022_AMD64_REQUIRED")
        reject_reparse(self.root)
        reject_reparse(self.data)
        index, manifest_name = validate_payload(archive)
        existing = self.scm.query()
        if existing or self.root.exists() or self.data.exists():
            marker_path = self.root / "installation.json"
            reject_reparse(marker_path)
            if not existing or not marker_path.is_file(): raise LocalError("EXISTING_RESOURCE_NOT_OWNED")
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            if (marker.get("service") != SERVICE_NAME or marker.get("account") != account
                    or existing["account"].casefold() != account.casefold() or existing["binary"] != binary_command(self.root)):
                raise LocalError("EXISTING_SERVICE_BINDING_MISMATCH")
            if marker.get("files") != index["files"]: raise LocalError("UPDATE_REQUIRES_APPROVED_MIGRATION")
            integrity(self.root)
            return {"state": "ALREADY_INSTALLED_STATE_PRESERVED", "account_policy": "CANDIDATE_NOT_APPROVED"}
        created_root = created_data = created_service = False
        try:
            self.root.mkdir(parents=False)
            created_root = True
            self.data.mkdir(parents=False)
            created_data = True
            # 파일 복사 전에 일반 사용자 상속 쓰기를 차단. SCM 등록 후 service SID를 추가한다.
            self.acl(self.root, None, writable=False)
            self.acl(self.data, None, writable=False)
            with zipfile.ZipFile(archive) as bundle:
                for name in list(index["files"]) + ["payload-manifest.json"]:
                    dest = self.root / PurePosixPath(name)
                    reject_reparse(dest)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with dest.open("xb") as stream: stream.write(bundle.read(name))
            self.scm.create(binary_command(self.root), account)
            created_service = True
            service_sid = self.sid_lookup("NT SERVICE\\" + SERVICE_NAME)
            account_sid = self.sid_lookup(account)
            self.acl(self.root, service_sid, writable=False)
            self.acl(self.data, service_sid, writable=True)
            for path in self.root.rglob("*"):
                self.acl(path, service_sid, writable=False)
            config = {"format": 1, "candidate": candidate, "service_sid": service_sid, "account_sid": account_sid,
                      "install_root": str(self.root), "data_root": str(self.data),
                      "manifest_path": str(self.root / manifest_name), "transport_enabled": False, "central_config": None}
            (self.root / "service-local.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
            marker = {"service": SERVICE_NAME, "account": account, "files": index["files"], "development_unsigned": True}
            (self.root / "installation.json").write_text(json.dumps(marker, indent=2), encoding="utf-8")
            for file in ("service-local.json", "installation.json"):
                self.acl(self.root / file, service_sid, writable=False)
            self.scm.start()
            return {"state": "INSTALLED_LOCAL_ONLY", "account_policy": "CANDIDATE_NOT_APPROVED"}
        except Exception:
            # 이번 transaction이 새로 만든 자원만 제거한다. 중지 실패 시 파일/state를 보존한다.
            if created_service:
                self.scm.stop()
                self.scm.delete()
            if created_root: remove_created_tree(self.root, self.root)
            if created_data: remove_created_tree(self.data, self.data)
            raise

    def uninstall(self):
        reject_reparse(self.root)
        reject_reparse(self.data)
        marker_path = self.root / "installation.json"
        reject_reparse(marker_path)
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        current = self.scm.query()
        if (marker.get("service") != SERVICE_NAME or not current or current["binary"] != binary_command(self.root)
                or current["account"].casefold() != marker.get("account", "").casefold()):
            raise LocalError("UNINSTALL_BINDING_REJECTED")
        integrity(self.root)
        allowed = set(marker["files"]) | {"payload-manifest.json", "service-local.json", "installation.json"}
        actual = {path.relative_to(self.root).as_posix() for path in self.root.rglob("*") if path.is_file()}
        if actual != allowed: raise LocalError("UNINSTALL_UNEXPECTED_FILES_PRESERVED")
        allowed_dirs = {parent.as_posix() for name in allowed for parent in PurePosixPath(name).parents if parent.as_posix() != "."}
        actual_dirs = {path.relative_to(self.root).as_posix() for path in self.root.rglob("*") if path.is_dir()}
        if actual_dirs != allowed_dirs: raise LocalError("UNINSTALL_UNEXPECTED_DIRECTORIES_PRESERVED")
        self.scm.stop()
        self.scm.delete()
        remove_created_tree(self.root, self.root)
        # 운영 credential/로그/state 및 계정/CA는 자동 삭제하거나 revoke하지 않는다.
        return {"state": "UNINSTALLED_LOCAL_STATE_RETAINED", "central_revocation": "NOT_REQUESTED"}
