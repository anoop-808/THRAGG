import pytest

from thragg import (
    DEFAULT_MODULE_REGISTRY,
    ModuleRegistration,
    ModuleRegistry,
)


def test_module_registry_exposes_metadata_and_resolves_modules():
    assert DEFAULT_MODULE_REGISTRY.resolve("/tmp/auth.log").module_name == "modules.logs"
    assert DEFAULT_MODULE_REGISTRY.resolve("/tmp/scan.xml").module_name == "modules.nmap"
    assert DEFAULT_MODULE_REGISTRY.resolve("/tmp/unknown.txt") is None
    assert {
        item["name"] for item in DEFAULT_MODULE_REGISTRY.metadata()
    } >= {"logs", "nmap", "zap", "identity", "cloud"}


def test_module_registry_validates_registration_contract():
    registry = ModuleRegistry()

    with pytest.raises(TypeError, match="ModuleRegistration"):
        registry.register(object())

    with pytest.raises(ValueError, match="name"):
        registry.register(ModuleRegistration("", "modules.logs", lambda _: True))

    with pytest.raises(ValueError, match="module_name"):
        registry.register(ModuleRegistration("logs", "", lambda _: True))

    with pytest.raises(TypeError, match="predicate"):
        registry.register(ModuleRegistration("logs", "modules.logs", "bad"))

    registry.register(ModuleRegistration("logs", "modules.logs", lambda _: True))
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register(ModuleRegistration("logs", "modules.logs", lambda _: True))
