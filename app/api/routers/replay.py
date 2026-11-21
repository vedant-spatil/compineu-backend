"""Scenario console endpoints (admin only), used by the dashboard's scenario buttons.

  POST /api/replay/reset               stop replays, supersede active cases, clear replayed events, undo PB1/PB2
  GET  /api/replay/status              every run's progress: sent, outcomes, detection result
  POST /api/replay/{scenario}?speed=60 start a scenario (S1, S1b, S1c, S1d, S2, S5, D1-D4, EG1-8, EF1-5)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import db_session, require_role
from app.portal import replay

router = APIRouter(prefix="/api/replay", tags=["replay"], dependencies=[Depends(require_role("admin"))])


@router.post("/reset")
def reset(db: Session = Depends(db_session)) -> dict[str, Any]:
    return replay.reset(db)


@router.get("/status")
def status() -> dict[str, Any]:
    return replay.status()


@router.post("/{scenario}")
def start(scenario: str, speed: float = Query(replay.DEFAULT_SPEED, ge=1, le=600)) -> dict[str, Any]:
    try:
        return replay.start(scenario, speed)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown scenario {scenario}") from None
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
