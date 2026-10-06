"""하드닝 전 레지스트리 값을 로컬 JSON 스냅샷으로 영구 보관한다."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from .models import PolicySnapshot, RegistrySnapshot, RollbackResult


class SnapshotError(RuntimeError):
    pass


class SnapshotStore:
    def __init__(self, directory: str | Path = "results/hardening-snapshots") -> None:
        self.directory = Path(directory)

    def create(self, *, code: str, plan_id: str, path: str, value_name: str,
               captured: dict) -> RegistrySnapshot:
        if set(captured) != {"exists", "value", "registry_type"}:
            raise SnapshotError("captured registry value format is invalid")
        if not isinstance(captured["exists"], bool):
            raise SnapshotError("captured registry existence flag is invalid")
        if captured["exists"] and not isinstance(captured["registry_type"], int):
            raise SnapshotError("captured registry type is invalid")
        snapshot = RegistrySnapshot(
            snapshot_id=str(uuid4()), code=code, registry_path=path,
            value_name=value_name, value_type=captured.get("registry_type"),
            previous_value=captured.get("value"), existed=bool(captured.get("exists")),
            timestamp=datetime.now(timezone.utc).isoformat(), plan_id=plan_id,
        )
        self._write(snapshot.snapshot_id, {**asdict(snapshot), "rollback_results": []})
        return snapshot

    def create_transaction(self, *, code, plan_id, path, value_name, captured):
        snapshot = PolicySnapshot(
            snapshot_id=str(uuid4()), code=code, registry_path=path,
            value_name=value_name, targets=captured["targets"],
            timestamp=datetime.now(timezone.utc).isoformat(), plan_id=plan_id,
        )
        self._write(snapshot.snapshot_id, {**asdict(snapshot), "rollback_results": []})
        return snapshot

    def load(self, snapshot_id: str) -> RegistrySnapshot | PolicySnapshot:
        data = self._read(snapshot_id)
        try:
            model = PolicySnapshot if "targets" in data else RegistrySnapshot
            snapshot = model(**{key: data[key] for key in model.__dataclass_fields__})
            if snapshot.snapshot_id != str(UUID(snapshot_id)):
                raise ValueError("snapshot id does not match the requested file")
            return snapshot
        except (KeyError, TypeError, ValueError) as exc:
            raise SnapshotError("snapshot format is invalid") from exc

    def record_rollback(self, result: RollbackResult) -> None:
        data = self._read(result.snapshot_id)
        records = data.setdefault("rollback_results", [])
        records.append(asdict(result))
        self._write(result.snapshot_id, data)

    def has_successful_rollback(self, snapshot_id: str) -> bool:
        return any(record.get("success") for record in self._read(snapshot_id).get("rollback_results", []))

    def _path(self, snapshot_id: str) -> Path:
        try:
            normalized = str(UUID(snapshot_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise SnapshotError("snapshot id is invalid") from exc
        return self.directory / f"{normalized}.json"

    def _read(self, snapshot_id: str) -> dict:
        try:
            return json.loads(self._path(snapshot_id).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise SnapshotError("snapshot does not exist") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise SnapshotError("snapshot cannot be read") from exc

    def _write(self, snapshot_id: str, data: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        destination = self._path(snapshot_id)
        temporary = destination.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temporary, destination)
        except OSError as exc:
            raise SnapshotError("snapshot cannot be saved") from exc
