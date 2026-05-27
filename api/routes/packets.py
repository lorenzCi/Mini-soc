from fastapi import APIRouter, Depends, Query
import pymysql

from api.db.connection import get_db
from api.services import packets as packets_service

router = APIRouter(tags=["packets"])


@router.get("/packets")
def get_packets(
    limit: int = Query(50, ge=1, le=500, description="Max rows to return"),
    conn: pymysql.Connection = Depends(get_db),
) -> dict:
    items = packets_service.list_packets(conn, limit=limit)
    return {"count": len(items), "items": items}
