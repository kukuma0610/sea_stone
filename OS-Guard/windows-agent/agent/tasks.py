from typing import Any


class InvalidTask(ValueError):
    pass


def validate_check_task(task: dict[str, Any]) -> dict[str, Any]:
    """Accept only the read-only CHECK task envelope."""
    if not isinstance(task, dict):
        raise InvalidTask("task must be an object")
    if task.get("action") != "CHECK":
        raise InvalidTask("only CHECK tasks are supported")
    if task.get("scan_scope") not in {"FULL", "PARTIAL"}:
        raise InvalidTask("scan_scope must be FULL or PARTIAL")
    if task["scan_scope"] == "PARTIAL":
        item_ids = task.get("item_ids")
        if not isinstance(item_ids, list) or not item_ids or not all(
            isinstance(item_id, str) and item_id.startswith("W-") for item_id in item_ids
        ):
            raise InvalidTask("PARTIAL CHECK requires Windows item_ids")
    forbidden = {"command", "script", "powershell", "shell", "argv", "args"}
    if forbidden.intersection(task):
        raise InvalidTask("command execution fields are not accepted")
    return task

