from fastapi import APIRouter

from api.routes.alerts import router as alerts_router
from api.routes.packets import router as packets_router
from api.routes.rules import router as rules_router
from api.routes.stats import router as stats_router

api_router = APIRouter()
api_router.include_router(alerts_router)
api_router.include_router(packets_router)
api_router.include_router(rules_router)
api_router.include_router(stats_router)
