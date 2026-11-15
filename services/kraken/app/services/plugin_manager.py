from __future__ import annotations
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from loguru import logger
from app.core.config import settings
from app.core.event_bus import event_bus

PLUGINS_DIR = Path(settings.DATA_DIR) / "plugins"
PLUGIN_MANIFEST_FILE = PLUGINS_DIR / "manifest.json"

BUILTIN_PLUGINS_DIR = Path(__file__).resolve().parent.parent / "plugins"

HOOK_POINTS = [
    "attack.ingested",
    "attack.before_save",
    "attack.after_save",
    "sandbox.created",
    "sandbox.destroyed",
    "malware.detected",
    "export.csv",
    "export.json",
    "export.pdf",
    "report.generated",
    "system.startup",
    "system.shutdown",
]


class PluginInfo:
    def __init__(self, pid: str, manifest: dict):
        self.id: str = pid
        self.name: str = manifest.get("name", pid)
        self.version: str = manifest.get("version", "0.1.0")
        self.description: str = manifest.get("description", "")
        self.author: str = manifest.get("author", "")
        self.hooks: List[str] = manifest.get("hooks", [])
        self.enabled: bool = manifest.get("enabled", True)
        self.config: Dict[str, Any] = manifest.get("config", {})
        self.is_builtin: bool = manifest.get("is_builtin", False)
        self.module: Optional[Any] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "hooks": self.hooks,
            "enabled": self.enabled,
            "config": self.config,
            "is_builtin": self.is_builtin,
        }


class PluginManager:
    def __init__(self):
        self._plugins: Dict[str, PluginInfo] = {}
        self._initialized = False

    @property
    def plugins(self) -> List[PluginInfo]:
        return list(self._plugins.values())

    def get(self, pid: str) -> Optional[PluginInfo]:
        return self._plugins.get(pid)

    async def initialize(self) -> None:
        if self._initialized:
            return
        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)

        if not PLUGIN_MANIFEST_FILE.exists():
            self._write_manifest({})

        self._load_builtin_plugins()
        self._load_user_plugins()

        await self._register_hooks()
        self._initialized = True
        logger.info(f"Plugin manager initialized: {len(self._plugins)} plugins loaded")

    def _load_builtin_plugins(self) -> None:
        if not BUILTIN_PLUGINS_DIR.exists():
            return
        for entry in sorted(BUILTIN_PLUGINS_DIR.iterdir()):
            if entry.is_dir() and (entry / "__init__.py").exists():
                manifest_path = entry / "plugin.json"
                if manifest_path.exists():
                    try:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        manifest["is_builtin"] = True
                        pid = manifest.get("id", entry.name)
                        if pid not in self._plugins:
                            self._plugins[pid] = PluginInfo(pid, manifest)
                            logger.info(f"  Loaded built-in plugin: {pid} v{manifest.get('version', '?')}")
                    except Exception as e:
                        logger.warning(f"  Failed to load built-in plugin {entry.name}: {e}")

    def _load_user_plugins(self) -> None:
        manifest_data = self._read_manifest()
        for pid, data in manifest_data.items():
            if pid not in self._plugins:
                data["is_builtin"] = data.get("is_builtin", False)
                self._plugins[pid] = PluginInfo(pid, data)
                logger.info(f"  Loaded user plugin: {pid}")

    async def _register_hooks(self) -> None:
        for plugin in self._plugins.values():
            if plugin.enabled:
                await self._activate_plugin(plugin)

    async def _activate_plugin(self, plugin: PluginInfo) -> None:
        try:
            module_path = f"app.plugins.{plugin.id}"
            if plugin.is_builtin:
                mod = importlib.import_module(module_path)
            else:
                if not plugin.module:
                    spec = importlib.util.spec_from_file_location(
                        plugin.id,
                        str(PLUGINS_DIR / plugin.id / "__init__.py"),
                    )
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                    else:
                        raise ImportError(f"Cannot load user plugin {plugin.id}")
                else:
                    mod = plugin.module

            plugin.module = mod
            registered = 0
            for hook in plugin.hooks:
                handler_name = f"on_{hook.replace('.', '_')}"
                handler = getattr(mod, handler_name, None)
                if handler and inspect.iscoroutinefunction(handler):
                    event_bus.subscribe(hook, handler, plugin.id)
                    registered += 1
            logger.info(f"  Plugin '{plugin.id}' activated: {registered} hooks registered")
        except Exception as e:
            logger.error(f"  Failed to activate plugin '{plugin.id}': {e}")

    async def _deactivate_plugin(self, plugin: PluginInfo) -> None:
        event_bus.clear_plugin_handlers(plugin.id)
        plugin.module = None
        logger.info(f"  Plugin '{plugin.id}' deactivated")

    async def enable_plugin(self, pid: str) -> Optional[PluginInfo]:
        plugin = self._plugins.get(pid)
        if not plugin:
            return None
        if plugin.enabled:
            return plugin
        plugin.enabled = True
        await self._activate_plugin(plugin)
        self._persist_plugin(plugin)
        return plugin

    async def disable_plugin(self, pid: str) -> Optional[PluginInfo]:
        plugin = self._plugins.get(pid)
        if not plugin:
            return None
        if not plugin.enabled:
            return plugin
        plugin.enabled = False
        await self._deactivate_plugin(plugin)
        self._persist_plugin(plugin)
        return plugin

    def update_config(self, pid: str, config: dict) -> Optional[PluginInfo]:
        plugin = self._plugins.get(pid)
        if not plugin:
            return None
        plugin.config = config
        self._persist_plugin(plugin)
        return plugin

    async def install_plugin(self, pid: str, manifest: dict) -> Optional[PluginInfo]:
        if pid in self._plugins:
            return None
        manifest["is_builtin"] = False
        manifest["enabled"] = manifest.get("enabled", True)
        self._plugins[pid] = PluginInfo(pid, manifest)
        self._write_manifest({p.id: p.to_dict() for p in self._plugins.values()})
        plugin = self._plugins[pid]
        if plugin.enabled:
            await self._activate_plugin(plugin)
        return plugin

    async def uninstall_plugin(self, pid: str) -> bool:
        plugin = self._plugins.get(pid)
        if not plugin or plugin.is_builtin:
            return False
        if plugin.enabled:
            await self._deactivate_plugin(plugin)
        del self._plugins[pid]
        self._write_manifest({p.id: p.to_dict() for p in self._plugins.values()})
        return True

    def _persist_plugin(self, plugin: PluginInfo) -> None:
        manifest_data = self._read_manifest()
        manifest_data[plugin.id] = plugin.to_dict()
        self._write_manifest(manifest_data)

    def _read_manifest(self) -> dict:
        try:
            return json.loads(PLUGIN_MANIFEST_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _write_manifest(self, data: dict) -> None:
        PLUGIN_MANIFEST_FILE.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )

    async def shutdown(self) -> None:
        for plugin in self._plugins.values():
            if plugin.enabled:
                try:
                    await event_bus.emit("system.shutdown", plugin_id=plugin.id)
                except Exception:
                    pass
        logger.info("Plugin manager shut down")


plugin_manager = PluginManager()
