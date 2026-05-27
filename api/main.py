"""
Mini SOC — read-only FastAPI API.

Run from project root:
  pip install -r requirements.txt
  uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import api_router

app = FastAPI(
    title="Mini SOC API",
    description="Read-only API for alerts, packets, detection rules, and stats.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
