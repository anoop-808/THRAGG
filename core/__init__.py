"""THRAGG core public API."""

from importlib import import_module
from typing import Any

_PACKAGES = (
    ".foundation",
    ".correlation",
    ".attack_chain",
    ".risk",
    ".executive",
    ".reporting",
    ".dashboard",
    ".shared",
)

_EXPORTS: dict[str, str] = {}
for _package_name in _PACKAGES:
    _package = import_module(_package_name, __name__)
    for _name in getattr(_package, "__all__", ()):
        _EXPORTS[_name] = _package_name

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Load public core symbols from their migrated packages."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(_EXPORTS[name], __name__), name)
    globals()[name] = value
    return value
