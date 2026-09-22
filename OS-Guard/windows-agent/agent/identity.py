import json
import uuid
from pathlib import Path

from . import AGENT_VERSION


class AgentIdentity:
    def __init__(self, agent_id: str, version: str = AGENT_VERSION):
        self.agent_id = agent_id
        self.version = version

    @classmethod
    def load_or_create(cls, path: Path) -> "AgentIdentity":
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(str(data["agent_id"]), str(data.get("agent_version", AGENT_VERSION)))

        identity = cls(f"agt-win-{uuid.uuid4()}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"agent_id": identity.agent_id, "agent_version": identity.version}, indent=2),
            encoding="utf-8",
        )
        return identity

