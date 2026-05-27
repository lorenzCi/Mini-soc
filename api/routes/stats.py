from fastapi import APIRouter, Depends, Query
import pymysql

from api.db.connection import get_db
from api.services import stats as stats_service

router = APIRouter(tags=["stats"])


@router.get("/stats")
def get_stats(
    top_ips: int = Query(10, ge=1, le=50, alias="top_ips", description="Top source IPs limit"),
    conn: pymysql.Connection = Depends(get_db),
) -> dict:
    return stats_service.get_stats(conn, top_ips_limit=top_ips)
