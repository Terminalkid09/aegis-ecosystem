from fastapi import APIRouter, Depends, HTTPException, Request
from app.services.plugin_manager import plugin_manager, HOOK_POINTS
from app.core.event_bus import event_bus
from app.api.v1.endpoints.deps import get_current_admin

router = APIRouter(prefix="/plugins", tags=["plugins"])


@router.get("/")
async def list_plugins(_=Depends(get_current_admin)):
    return [p.to_dict() for p in plugin_manager.plugins]


@router.get("/hooks")
async def list_hooks(_=Depends(get_current_admin)):
    return {
        "hook_points": HOOK_POINTS,
        "active_hooks": {
            event: list(event_bus.get_subscribed_plugins(event))
            for event in HOOK_POINTS
        },
    }


@router.post("/{pid}/enable")
async def enable_plugin(pid: str, _=Depends(get_current_admin)):
    plugin = await plugin_manager.enable_plugin(pid)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin.to_dict()


@router.post("/{pid}/disable")
async def disable_plugin(pid: str, _=Depends(get_current_admin)):
    plugin = await plugin_manager.disable_plugin(pid)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin.to_dict()


@router.put("/{pid}/config")
async def update_plugin_config(pid: str, config: dict, _=Depends(get_current_admin)):
    plugin = plugin_manager.update_config(pid, config)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin.to_dict()


@router.post("/{pid}/install")
async def install_plugin(pid: str, manifest: dict, _=Depends(get_current_admin)):
    plugin = await plugin_manager.install_plugin(pid, manifest)
    if not plugin:
        raise HTTPException(status_code=409, detail="Plugin already exists")
    return plugin.to_dict()


@router.delete("/{pid}")
async def uninstall_plugin(pid: str, _=Depends(get_current_admin)):
    success = await plugin_manager.uninstall_plugin(pid)
    if not success:
        raise HTTPException(status_code=404, detail="Plugin not found or is built-in")
    return {"status": "uninstalled", "plugin_id": pid}
