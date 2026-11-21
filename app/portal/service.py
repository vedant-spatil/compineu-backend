"""The mock portal's behaviour, independent of HTTP, so the replay can call it in-process at 60x.

Rules (agreed with detection):
- Out-of-portfolio reads are ALLOWED and recorded. Detecting them is the point; the portal does not prevent them.
- An agent is refused (403) only when the credential is disabled or HR status is suspended (PB1). A terminated agent
  whose credential is still enabled gets through: that gap is scenario S5.
- A partner key is refused (403) only when disabled (PB2). The partner API returns ANY existing claim, assigned or
  not (the broken object-level authorisation that P1 detects). A claim that does not exist is a 404.
- Every call is an access event, refused ones included (outcome "denied" for 403, "not_found" for 404), so
  blocked probing still counts.
- Columns follow migrations 0011 and 0012: every event has a tier (login and search are T3, internal) and a
  resource_id; views and claims carry policyholder_id; exports are resource_type "export_file".
- Timestamps are plain UTC without a timezone.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.portal.store import PortalStore

T1_FIELDS = {"diagnosis", "claim_amount", "hospital", "discharge_summary", "aadhaar", "pan", "bank_account"}
SEARCH_LIMIT = 20


class PortalError(Exception):
    def __init__(self, status: int, detail: str, event_id: str):
        super().__init__(detail)
        self.status, self.detail, self.event_id = status, detail, event_id


@dataclass
class Ctx:
    """Who is calling and from where. The replay sets ts, event_id and labels from the scenario file."""
    actor_id: str
    ip: str | None = None
    device: str | None = None
    city: str | None = None
    country: str | None = None
    session_id: str | None = None
    ts: datetime | str | None = None
    event_id: str | None = None
    labels: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _ts(ctx: Ctx) -> str:
    ts = ctx.ts or _now()
    if isinstance(ts, datetime):
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.strftime("%Y-%m-%dT%H:%M:%S")
    return ts


def _event(ctx: Ctx, actor_type: str, action: str, rtype: str, rid: str | None, tier: str | None, records: int,
           outcome: str, channel: str, detail: dict[str, Any] | None = None,
           policyholder_id: str | None = None) -> dict[str, Any]:
    e = {"event_id": ctx.event_id or f"ev-p-{uuid.uuid4().hex[:16]}", "ts": _ts(ctx), "actor_id": ctx.actor_id,
         "actor_type": actor_type, "action": action, "resource_type": rtype, "resource_id": rid or "-",
         "policyholder_id": policyholder_id, "tier": tier or "T3", "records": records, "outcome": outcome,
         "channel": channel, "ip": ctx.ip, "device": ctx.device, "city": ctx.city, "country": ctx.country,
         "session_id": ctx.session_id}
    if detail:
        e["detail"] = detail
    if ctx.labels:
        e["labels"] = ctx.labels
    return e


def tier_of(ph: dict[str, Any]) -> str:
    return "T1" if str(ph.get("product", "")).lower() == "health" else "T2"


def _agent_gate(store: PortalStore, ctx: Ctx, action: str, rtype: str, rid: str | None) -> dict[str, Any]:
    agent = store.agent(ctx.actor_id)
    reason = None
    if agent is None:
        reason = "unknown agent"
    elif agent.get("credential_enabled") is False or str(agent.get("hr_status", "")).lower() == "suspended":
        reason = "access suspended"
    if reason:
        e = _event(ctx, "agent", action, rtype, rid, None, 0, "denied", "portal", {"reason": reason, "http": 403},
                   rid if rtype == "policyholder" else None)
        store.record(e)
        raise PortalError(403, reason, e["event_id"])
    return agent


# ---------------------------------------------------------------------------------------------- agent portal
def login(store: PortalStore, ctx: Ctx) -> dict[str, Any]:
    _agent_gate(store, ctx, "login", "session", ctx.session_id)
    e = _event(ctx, "agent", "login", "session", ctx.session_id or "portal", None, 0, "allowed", "portal")
    store.record(e)
    return {"event_id": e["event_id"], "session_id": ctx.session_id}


def view(store: PortalStore, ctx: Ctx, policyholder_id: str) -> dict[str, Any]:
    _agent_gate(store, ctx, "view", "policyholder", policyholder_id)
    ph = store.policyholder(policyholder_id)
    if ph is None:
        e = _event(ctx, "agent", "view", "policyholder", policyholder_id, None, 0, "not_found", "portal",
                   {"reason": "not found", "http": 404}, policyholder_id)
        store.record(e)
        raise PortalError(404, "policyholder not found", e["event_id"])
    e = _event(ctx, "agent", "view", "policyholder", policyholder_id, tier_of(ph), 1, "allowed", "portal",
               policyholder_id=policyholder_id)
    store.record(e)
    return {"event_id": e["event_id"], "policyholder": ph}


def parse_query(q: str) -> tuple[dict[str, str], str]:
    """'city=Nagpur product=health anita' -> ({'city': 'Nagpur', 'product': 'health'}, 'anita')."""
    filters, words = {}, []
    for part in (q or "").split():
        if "=" in part:
            k, _, v = part.partition("=")
            if k in ("city", "product", "branch"):
                filters[k] = v
        else:
            words.append(part)
    return filters, " ".join(words)


def search(store: PortalStore, ctx: Ctx, q: str) -> dict[str, Any]:
    _agent_gate(store, ctx, "search", "search", q)
    filters, text = parse_query(q)
    rows = store.search(filters, text, SEARCH_LIMIT)
    results = [{"policyholder_id": r.get("policyholder_id"), "name": r.get("name"), "city": r.get("city")} for r in rows]
    # records=0: a result list shows names only; opening a record is a separate view event.
    e = _event(ctx, "agent", "search", "search", q, None, 0, "allowed", "portal", {"results_listed": len(results)})
    store.record(e)
    return {"event_id": e["event_id"], "results": results}


def export(store: PortalStore, ctx: Ctx, query: str, rows: int, fields: list[str]) -> dict[str, Any]:
    export_id = f"EXP-{uuid.uuid4().hex[:8].upper()}"
    _agent_gate(store, ctx, "export", "export_file", export_id)
    filters, _ = parse_query(query)
    sensitive = bool(T1_FIELDS & {f.lower() for f in fields}) or filters.get("product", "").lower() == "health"
    e = _event(ctx, "agent", "export", "export_file", export_id, "T1" if sensitive else "T2", int(rows), "allowed",
               "portal",
               {"rows": int(rows), "fields": fields, "query": query, "format": "csv"})
    store.record(e)
    return {"event_id": e["event_id"], "export_id": export_id, "rows": int(rows), "status": "ready"}


# ---------------------------------------------------------------------------------------------- partner API
def partner_claim(store: PortalStore, ctx: Ctx, claim_id: str) -> dict[str, Any]:
    key = store.partner_key(ctx.actor_id)
    if key is None or key.get("enabled") is False:
        reason = "unknown key" if key is None else "key disabled"
        e = _event(ctx, "partner_key", "api_get", "claim", claim_id, "T1", 0, "denied", "api",
                   {"reason": reason, "http": 403})
        store.record(e)
        raise PortalError(403, reason, e["event_id"])
    claim = store.claim(claim_id)
    if claim is None:
        e = _event(ctx, "partner_key", "api_get", "claim", claim_id, "T1", 0, "not_found", "api",
                   {"reason": "not found", "http": 404})
        store.record(e)
        raise PortalError(404, "claim not found", e["event_id"])
    e = _event(ctx, "partner_key", "api_get", "claim", claim_id, "T1", 1, "allowed", "api",
               policyholder_id=claim.get("policyholder_id"))
    store.record(e)
    return {"event_id": e["event_id"], "claim": claim}
