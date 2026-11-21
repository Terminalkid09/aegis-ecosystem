from fastapi import APIRouter

from app.api.v1.endpoints import auth, events, export, containers, health, plugins, reports, ops

tags_metadata = [
    {
        "name": "Authentication",
        "description": "User authentication and session management. Login returns JWT token in both response body and HttpOnly cookie.",
    },
    {
        "name": "Events",
        "description": "Attack event querying and management. Events are ingested by honeypot sensors.",
    },
    {
        "name": "Export",
        "description": "Data export in CSV, JSON, and PDF formats. Rate limited to 30 requests/minute.",
    },
    {
        "name": "Containers",
        "description": "Sandbox container management for interactive attack analysis.",
    },
    {
        "name": "Health",
        "description": "System health checks for monitoring and orchestration.",
    },
    {
        "name": "Plugins",
        "description": "Plugin management: enable, disable, configure, install, and uninstall plugins with event-driven hook system.",
    },
    {
        "name": "Reports",
        "description": "Professional report generation with executive summaries, findings matrices, recommendations, HTML preview, and PDF download.",
    },
    {
        "name": "Operations",
        "description": "Campaigns, sensor fleet, topology and shadow Lab metadata.",
    },
]

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router, tags=["Authentication"])
api_router.include_router(events.router, tags=["Events"])
api_router.include_router(export.router, tags=["Export"])
api_router.include_router(containers.router, tags=["Containers"])
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(plugins.router, tags=["Plugins"])
api_router.include_router(reports.router, tags=["Reports"])
api_router.include_router(ops.router, tags=["Operations"])
