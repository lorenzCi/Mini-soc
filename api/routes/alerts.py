from fastapi import APIRouter, Depends, Query
import pymysql

from shared.db.connection import get_db
from api.services import alerts as alerts_service

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=500, description="Max rows to return"),
    conn: pymysql.Connection = Depends(get_db),
) -> dict:
    items = alerts_service.list_alerts(conn, limit=limit)
    return {"count": len(items), "items": items}
