"""Mock insurer agent portal and TPA partner API (plan section 8). Each call writes an access event.

These stand in for the insurer's real systems in the demo, so they are not open to the internet: every call needs
an admin login of this app (the operator driving the demo), and the caller says which agent or key it acts as.

  GET  /api/portal/policyholders/{id}      X-Agent-Id    open one record (out-of-portfolio is allowed and recorded)
  GET  /api/portal/search?q=city=Nagpur    X-Agent-Id    list names only (records=0)
  POST /api/portal/export                  X-Agent-Id    {"query", "rows", "fields"}
  POST /api/portal/login                   X-Agent-Id
  GET  /api/partner/claims/{claim_id}      X-Api-Key     any existing claim (the flaw P1 detects); 404 if none

Optional context headers: X-Device-Id, X-Session-Id, X-Client-City, X-Client-Country, X-Client-Ip (the demo
operator simulates the agent's device and place; without X-Client-Ip the viewer IP from CloudFront is used).
403 when PB1 suspended the agent or PB2 disabled the key, 404 when the record does not exist; refused calls are
recorded too.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import db_session, require_role
from app.config import get_settings
from app.portal import service
from app.portal.store import DbStore, MemoryStore, PortalStore, StoreNotReady

router = APIRouter(prefix="/api", tags=["portal"], dependencies=[Depends(require_role("admin"))])


@lru_cache(maxsize=1)
def _fixture_store(path: str) -> MemoryStore:
    return MemoryStore.from_dir(path)


def get_store(db: Session = Depends(db_session)) -> PortalStore:
    mode = get_settings().portal_store
    if mode.startswith("fixture:"):
        return _fixture_store(mode.split(":", 1)[1])
    return DbStore(db)


def _ctx(request: Request, actor: str, device: str | None, session: str | None, city: str | None,
         country: str | None, ip: str | None) -> service.Ctx:
    fwd = request.headers.get("x-forwarded-for", "")
    viewer_ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else None)
    return service.Ctx(actor_id=actor, ip=ip or viewer_ip, device=device, session_id=session, city=city,
                       country=country)


def _call(fn, *args) -> dict[str, Any]:
    try:
        return fn(*args)
    except service.PortalError as exc:
        raise HTTPException(status_code=exc.status, detail={"error": exc.detail, "event_id": exc.event_id}) from None
    except StoreNotReady as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None


class ExportIn(BaseModel):
    query: str = ""
    rows: int = Field(ge=1, le=100_000)
    fields: list[str] = Field(default_factory=list, max_length=50)


Agent = Header(..., alias="X-Agent-Id", min_length=2, max_length=32)
Device = Header(None, alias="X-Device-Id", max_length=64)
Sess = Header(None, alias="X-Session-Id", max_length=64)
City = Header(None, alias="X-Client-City", max_length=64)
Country = Header(None, alias="X-Client-Country", max_length=2)
Ip = Header(None, alias="X-Client-Ip", max_length=45)


@router.post("/portal/login")
def portal_login(request: Request, agent: str = Agent, device: str | None = Device, session: str | None = Sess,
                 city: str | None = City, country: str | None = Country, ip: str | None = Ip,
                 store: PortalStore = Depends(get_store)) -> dict[str, Any]:
    return _call(service.login, store, _ctx(request, agent, device, session, city, country, ip))


@router.get("/portal/policyholders/{policyholder_id}")
def portal_view(policyholder_id: str, request: Request, agent: str = Agent, device: str | None = Device,
                session: str | None = Sess, city: str | None = City, country: str | None = Country,
                ip: str | None = Ip, store: PortalStore = Depends(get_store)) -> dict[str, Any]:
    return _call(service.view, store, _ctx(request, agent, device, session, city, country, ip), policyholder_id)


@router.get("/portal/search")
def portal_search(request: Request, q: str = Query("", max_length=200), agent: str = Agent,
                  device: str | None = Device, session: str | None = Sess, city: str | None = City,
                  country: str | None = Country, ip: str | None = Ip,
                  store: PortalStore = Depends(get_store)) -> dict[str, Any]:
    return _call(service.search, store, _ctx(request, agent, device, session, city, country, ip), q)


@router.post("/portal/export")
def portal_export(body: ExportIn, request: Request, agent: str = Agent, device: str | None = Device,
                  session: str | None = Sess, city: str | None = City, country: str | None = Country,
                  ip: str | None = Ip, store: PortalStore = Depends(get_store)) -> dict[str, Any]:
    return _call(service.export, store, _ctx(request, agent, device, session, city, country, ip), body.query,
                 body.rows, body.fields)


@router.get("/partner/claims/{claim_id}")
def partner_claim(claim_id: str, request: Request, key: str = Header(..., alias="X-Api-Key", max_length=64),
                  city: str | None = City, country: str | None = Country, ip: str | None = Ip,
                  store: PortalStore = Depends(get_store)) -> dict[str, Any]:
    return _call(service.partner_claim, store, _ctx(request, key, None, None, city, country, ip), claim_id)
