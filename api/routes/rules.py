from fastapi import APIRouter, Depends
import pymysql

from api.db.connection import get_db
from api.services import rules as rules_service

router = APIRouter(tags=["rules"])


@router.get("/rules")
def get_rules(conn: pymysql.Connection = Depends(get_db)) -> dict:
    items = rules_service.list_rules(conn)
    return {"count": len(items), "items": items}
