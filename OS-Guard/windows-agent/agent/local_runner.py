"""Offline, read-only Windows CHECK runner for Server 2022 VM validation."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .windows_checks import CheckObservation, KISA_SOURCES, NativeWindowsReadOnlyApi, collect_check


CHECK_IDS = tuple(f"W-{number:02d}" for number in range(1, 65))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _system_info() -> dict[str, Any]:
    version = platform.win32_ver()
    return {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "windows_edition": version[0],
        "windows_build": version[1],
        "architecture": platform.machine(),
        "administrator": _is_administrator(),
    }


def _safe_error(exc: Exception) -> str:
    message = f"{type(exc).__name__}: {exc}"
    for value in (os.environ.get("USERNAME"), os.environ.get("USERPROFILE")):
        if value:
            message = message.replace(value, "***")
    return message


def _unexpected_failure(item_id: str, exc: Exception) -> CheckObservation:
    return CheckObservation(
        item_id=item_id,
        status="UNABLE",
        reason_code="LOCAL_RUNNER_UNEXPECTED_ERROR",
        current_value={},
        observed_at=_now(),
        source_page=KISA_SOURCES.get(item_id, {}).get("page"),
        manual_review_required=True,
        evidence_redacted=True,
        error_reason=_safe_error(exc),
    )


def run_checks(
    *,
    api: Any | None = None,
    collector: Callable[[str, Any | None], CheckObservation] = collect_check,
    system_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    info = system_info or _system_info()
    read_only_api = api
    api_error: Exception | None = None
    if read_only_api is None:
        try:
            read_only_api = NativeWindowsReadOnlyApi()
        except Exception as exc:  # Each item must still produce an UNABLE result.
            api_error = exc

    checks: list[dict[str, Any]] = []
    for item_id in CHECK_IDS:
        try:
            observation = (
                _unexpected_failure(item_id, api_error)
                if api_error is not None
                else collector(item_id, read_only_api)
            )
        except Exception as exc:  # Isolate an unexpected collector failure to one W-code.
            observation = _unexpected_failure(item_id, exc)
        record = asdict(observation)
        record["evidence"] = record.pop("current_value")
        checks.append(record)

    counts = {status: sum(check["status"] == status for check in checks) for status in ("PASS", "FAIL", "NA", "UNABLE")}
    return {"mode": "LOCAL_READ_ONLY", "generated_at": _now(), "system": info, "summary": counts, "checks": checks}


def save_report(report: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return output.resolve()


def _default_output() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("results") / f"windows-check-{stamp}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run W-01 through W-64 locally without central API transmission")
    parser.add_argument("--output", type=Path, default=_default_output(), help="JSON report path")
    args = parser.parse_args()

    report = run_checks()
    system = report["system"]
    print(f"OS={system['os']} {system['release']} version={system['version']} build={system['windows_build']}")
    print(f"administrator={system['administrator']} mode={report['mode']} central_api=disabled")
    for check in report["checks"]:
        print(json.dumps({
            "item_id": check["item_id"], "status": check["status"],
            "error_reason": check["error_reason"],
            "manual_review": check["manual_review_required"], "evidence": check["evidence"],
        }, ensure_ascii=False))
    output = save_report(report, args.output)
    print(f"summary={json.dumps(report['summary'], ensure_ascii=False)}")
    print(f"output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
