import importlib
import inspect
import pkgutil

from core.base import ProtocolPlugin


class ProtocolRegistry:
    def __init__(self, package_name="protocols"):
        self.package_name = package_name
        self._plugins = {}

    def discover(self):
        package = importlib.import_module(self.package_name)
        for module_info in pkgutil.iter_modules(package.__path__):
            if module_info.name.startswith("_"):
                continue
            module = importlib.import_module(
                f"{self.package_name}.{module_info.name}"
            )
            for _, candidate in inspect.getmembers(module, inspect.isclass):
                if candidate is ProtocolPlugin:
                    continue
                if not issubclass(candidate, ProtocolPlugin):
                    continue
                if candidate.__module__ != module.__name__:
                    continue
                if not candidate.plugin_id:
                    continue
                if candidate.plugin_id in self._plugins:
                    raise RuntimeError(f"Plugin duplicado: {candidate.plugin_id}")
                self._plugins[candidate.plugin_id] = candidate
        return self

    def available(self):
        return dict(sorted(self._plugins.items()))

    def create(self, selected=None, config=None):
        names = selected or list(self.available())
        missing = sorted(set(names) - set(self._plugins))
        if missing:
            raise ValueError("Protocolos no disponibles: " + ", ".join(missing))
        return [self._plugins[name](config=config) for name in names]
