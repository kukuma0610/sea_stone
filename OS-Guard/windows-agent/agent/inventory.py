import platform
import socket
from typing import Any


def collect_inventory() -> dict[str, Any]:
    """Collect read-only host information; no OS configuration is changed."""
    return {
        "family": "WINDOWS" if platform.system().lower() == "windows" else platform.system().upper(),
        "version": platform.version(),
        "release": platform.release(),
        "hostname": socket.gethostname(),
    }

