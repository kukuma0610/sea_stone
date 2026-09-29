"""Independent Windows CHECK module registry."""

from importlib import import_module
from typing import Any, Callable

from .common import CheckObservation

Checker = Callable[[Any | None], CheckObservation]


def _load(item_id: str) -> Checker:
    module_name = item_id.lower().replace("-", "")
    module = import_module(f"{__name__}.{module_name}")
    return module.check


CHECK_REGISTRY: dict[str, Checker] = {
    f"W-{number:02d}": _load(f"W-{number:02d}") for number in range(1, 65)
}
