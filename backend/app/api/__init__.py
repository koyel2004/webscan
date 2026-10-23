"""
API Routes Registration
"""
from fastapi import APIRouter

from app.api.dashboard import router as dashboard_router
from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.methodology import router as methodology_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(reports_router)
api_router.include_router(dashboard_router)
api_router.include_router(methodology_router)

__all__ = ["api_router"]
