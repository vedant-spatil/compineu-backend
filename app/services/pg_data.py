"""Read access to the PolicyGuard tables (migrations 0011 and 0012): access_events, portfolios, agents,
partner_keys, partner_claim_assignments, context_records. See docs/ai_lane.md for the contract.

Schema conventions (0011): context_records.subject_agent is whose portfolio or leave the record is about (the
colleague Y); named_agent is who it authorises (the covering agent X); valid_from / valid_to are naive UTC, valid_to
exclusive. agents.usual_start_hour / usual_end_hour are IST hours. Portfolios also hold branch managers' team rows;
fetch_owners leaves managers out so a manager is never taken for the colleague being covered.

Everything here is plain SQL through sqlalchemy.text(), standard SQL only, so nothing imports Lane 1's ORM models and the
same statements run on Postgres and on SQLite (the offline checks). Results are plain frozen dataclasses.

Rules:
- Ground-truth columns (access_events.labels, alerts.is_laundering) are never selected.
- A failed statement rolls the session back (a failed Postgres transaction would break the next audit write) and raises
  PgDataError, which carries the table and the exception class name, never the SQL or its parameters.
- Values are read tolerantly: tier as 1, "1", "T1" or "Tier 1"; JSON as a value or as text; booleans as bool, 0/1 or text.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import DateTime, bindparam, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

CHUNK = 500

# resource_type values that mean "a policyholder's data" (or a claim, for partner keys). Open question for Lane 1.
POLICYHOLDER_RESOURCE_TYPES = frozenset({"policyholder", "policy", "claim", "customer"})


class PgDataError(RuntimeError):
    """A read failed. Only the table and the exception class name are kept, so logs never carry SQL or parameters."""

    def __init__(self, table: str, kind: str) -> None:
        super().__init__(f"{table}: {kind}")
        self.table = table
        self.kind = kind


@dataclass(frozen=True)
class AccessEvent:
    id: int
    ts: datetime
    actor_id: str
    actor_type: str
    action: str
    resource_type: str | None
    resource_id: str | None
    tier: int | None
    records: int
    outcome: str
    channel: str | None = None
    policyholder_id: str | None = None
    ip: str | None = None
    device: str | None = None
    city: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class AgentProfile:
    agent_id: str
    name: str | None = None
    branch: str | None = None
    channel: str | None = None
    hr_status: str | None = None
    manager_id: str | None = None
    usual_start_hour: int | None = None  # IST
    usual_end_hour: int | None = None  # IST
    home_city: str | None = None
    credential_enabled: bool = True
    known_devices: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PartnerKey:
    key_id: str
    partner: str | None = None
    enabled: bool = True
    assigned_claims: tuple[str, ...] = field(default_factory=tuple)
    known_ips: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ContextRecord:
    id: int
    type: str
    subject_agent: str | None = None  # whose portfolio or leave (colleague Y)
    payload: dict[str, Any] = field(default_factory=dict)  # untrusted text lives here; never used for authorship
    created_by: str | None = None
    created_at: datetime | None = None
    named_agent: str | None = None  # who it authorises (covering agent X)
    valid_from: datetime | None = None
    valid_to: datetime | None = None  # exclusive


# ---- tolerant converters -------------------------------------------------------------------------------------------

def to_utc(value: Any) -> datetime | None:
    """datetime, date or ISO string -> aware UTC datetime. A naive value is taken as UTC. Unparsable or None -> None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day)
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    else:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def db_ts(dt: datetime) -> datetime:
    """Query parameter form: naive UTC. (Postgres sessions are pinned to UTC in _rows, so timestamp and timestamptz
    columns both compare correctly.)"""
    return (dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)).replace(tzinfo=None)


def normalize_tier(value: Any) -> int | None:
    """1, '1', 'T1', 't1', 'Tier 1' -> 1. Anything outside 1..3 -> None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = int(value)
    else:
        digits = "".join(ch for ch in str(value) if ch.isdigit())
        if not digits:
            return None
        number = int(digits)
    return number if number in (1, 2, 3) else None


def parse_json(value: Any) -> Any:
    """JSON column -> Python. Text is decoded; bad text gives {}. dict and list pass through; None gives {}."""
    if value is None:
        return {}
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {}
    return {}


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "t", "true", "yes", "y")
    return bool(value)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _claims(value: Any) -> tuple[str, ...]:
    """assigned_claims as a JSON list, a JSON string of a list, or comma-separated text."""
    parsed: Any = value
    if isinstance(value, (bytes, bytearray)):
        parsed = value.decode("utf-8", "replace")
    if isinstance(parsed, str):
        stripped = parsed.strip()
        if stripped.startswith("["):
            parsed = parse_json(stripped)
        else:
            parsed = [part.strip() for part in stripped.split(",")]
    if isinstance(parsed, (list, tuple)):
        return tuple(str(item) for item in parsed if str(item).strip())
    return ()


def is_policyholder_access(ev: AccessEvent) -> bool:
    """True when the event reads a policyholder's (or claim's) data. Export events are not reads; they are counted apart."""
    if (ev.action or "").lower() == "export":
        return False
    kind = (ev.resource_type or "").strip().lower()
    rid = (ev.resource_id or "").strip().upper()
    return kind in POLICYHOLDER_RESOURCE_TYPES or rid.startswith("PH-")


def percentile(values: Sequence[float], q: float) -> float | None:
    """Linear interpolation between order statistics (the numpy default). None for an empty list."""
    if not values:
        return None
    ordered = sorted(float(v) for v in values)
    pos = max(0.0, min(1.0, q)) * (len(ordered) - 1)
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


# ---- statements ----------------------------------------------------------------------------------------------------

def _rows(db: Session, stmt: Any, table: str) -> list[Any]:
    """Runs one read. Any database error rolls the session back and becomes PgDataError."""
    try:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        return list(db.execute(stmt).all())
    except SQLAlchemyError as exc:
        db.rollback()
        raise PgDataError(table, type(exc).__name__) from None


def _chunks(items: Sequence[str]) -> list[list[str]]:
    unique = list(dict.fromkeys(str(i) for i in items if i is not None))
    return [unique[i:i + CHUNK] for i in range(0, len(unique), CHUNK)]


_EVENT_COLUMNS = ("id, ts, actor_id, actor_type, action, resource_type, resource_id, tier, records, outcome, channel, "
                  "ip, device, city, session_id, policyholder_id")


def fetch_events(db: Session, actor_id: str, start: datetime, end: datetime, limit: int = 20000) -> list[AccessEvent]:
    stmt = text(
        f"SELECT {_EVENT_COLUMNS} FROM access_events "
        "WHERE actor_id = :actor AND ts >= :start AND ts <= :end ORDER BY ts, id LIMIT :lim"
    ).bindparams(bindparam("start", type_=DateTime()), bindparam("end", type_=DateTime())).bindparams(
        actor=str(actor_id), start=db_ts(start), end=db_ts(end), lim=int(limit))
    out: list[AccessEvent] = []
    for r in _rows(db, stmt, "access_events"):
        ts = to_utc(r.ts)
        if ts is None:
            continue
        out.append(AccessEvent(
            id=int(r.id), ts=ts, actor_id=str(r.actor_id), actor_type=str(r.actor_type or "").lower(),
            action=str(r.action or "").lower(), resource_type=_as_str(r.resource_type), resource_id=_as_str(r.resource_id),
            tier=normalize_tier(r.tier), records=_as_int(r.records), outcome=str(r.outcome or "").lower(),
            channel=_as_str(r.channel), ip=_as_str(r.ip), device=_as_str(r.device), city=_as_str(r.city),
            session_id=_as_str(r.session_id), policyholder_id=_as_str(r.policyholder_id),
        ))
    return out


def fetch_daily_record_totals(db: Session, actor_id: str, start: datetime, end: datetime,
                              limit: int = 200000) -> dict[str, int]:
    """ISO date (UTC) -> records the actor read on that day (outcome 'allowed'). Summed in Python, not in SQL."""
    stmt = text(
        "SELECT ts, records FROM access_events "
        "WHERE actor_id = :actor AND outcome = 'allowed' AND ts >= :start AND ts < :end LIMIT :lim"
    ).bindparams(bindparam("start", type_=DateTime()), bindparam("end", type_=DateTime())).bindparams(
        actor=str(actor_id), start=db_ts(start), end=db_ts(end), lim=int(limit))
    totals: dict[str, int] = {}
    for r in _rows(db, stmt, "access_events"):
        ts = to_utc(r.ts)
        if ts is not None:
            key = ts.date().isoformat()
            totals[key] = totals.get(key, 0) + _as_int(r.records)
    return totals


def fetch_agents(db: Session, agent_ids: Sequence[str]) -> dict[str, AgentProfile]:
    out: dict[str, AgentProfile] = {}
    for chunk in _chunks(agent_ids):
        stmt = text(
            "SELECT agent_id, name, branch, channel, hr_status, manager_id, usual_start_hour, usual_end_hour, "
            "home_city, credential_enabled, known_devices FROM agents WHERE agent_id IN :ids"
        ).bindparams(bindparam("ids", expanding=True)).bindparams(ids=chunk)
        for r in _rows(db, stmt, "agents"):
            out[str(r.agent_id)] = AgentProfile(
                agent_id=str(r.agent_id), name=_as_str(r.name), branch=_as_str(r.branch), channel=_as_str(r.channel),
                hr_status=(_as_str(r.hr_status) or "").lower() or None, manager_id=_as_str(r.manager_id),
                usual_start_hour=None if r.usual_start_hour is None else _as_int(r.usual_start_hour),
                usual_end_hour=None if r.usual_end_hour is None else _as_int(r.usual_end_hour),
                home_city=_as_str(r.home_city), credential_enabled=_as_bool(r.credential_enabled),
                known_devices=_claims(r.known_devices),
            )
    return out


def fetch_partner_key(db: Session, key_id: str) -> PartnerKey | None:
    stmt = text("SELECT key_id, partner, enabled, known_ips FROM partner_keys WHERE key_id = :k").bindparams(
        k=str(key_id))
    rows = _rows(db, stmt, "partner_keys")
    if not rows:
        return None
    r = rows[0]
    claims = _rows(db, text("SELECT claim_id FROM partner_claim_assignments WHERE key_id = :k").bindparams(
        k=str(key_id)), "partner_claim_assignments")
    return PartnerKey(key_id=str(r.key_id), partner=_as_str(r.partner), enabled=_as_bool(r.enabled),
                      assigned_claims=tuple(str(c.claim_id) for c in claims), known_ips=_claims(r.known_ips))


def fetch_portfolio(db: Session, agent_id: str) -> set[str]:
    stmt = text("SELECT policyholder_id FROM portfolios WHERE agent_id = :a").bindparams(a=str(agent_id))
    return {str(r.policyholder_id) for r in _rows(db, stmt, "portfolios")}


def fetch_owners(db: Session, policyholder_ids: Sequence[str]) -> dict[str, list[str]]:
    """policyholder id -> the agents whose portfolio holds it. Policyholders with no owner are absent from the result.
    Branch managers (anyone who is some agent's manager_id) are left out: their portfolio rows are their team's."""
    out: dict[str, list[str]] = {}
    for chunk in _chunks(policyholder_ids):
        stmt = text("SELECT p.policyholder_id, p.agent_id FROM portfolios p WHERE p.policyholder_id IN :ids "
                    "AND NOT EXISTS (SELECT 1 FROM agents m WHERE m.manager_id = p.agent_id)").bindparams(
            bindparam("ids", expanding=True)).bindparams(ids=chunk)
        for r in _rows(db, stmt, "portfolios"):
            owners = out.setdefault(str(r.policyholder_id), [])
            if str(r.agent_id) not in owners:
                owners.append(str(r.agent_id))
    return out


def fetch_context_records(db: Session, subject_agents: Sequence[str], types: Sequence[str], *,
                          created_from: datetime | None = None, created_to: datetime | None = None,
                          limit: int = 100) -> list[ContextRecord]:
    """Newest first. Matches records whose subject_agent OR named_agent is one of `subject_agents`, so passing
    [X, *owners] returns the owners' leave and records naming X. "type" is quoted (a keyword in some dialects)."""
    subjects = list(dict.fromkeys(str(s) for s in subject_agents if s is not None))
    kinds = list(dict.fromkeys(str(t) for t in types))
    if not subjects or not kinds:
        return []
    sql = ('SELECT id, "type", subject_agent, payload, created_by, created_at, named_agent, valid_from, valid_to '
           'FROM context_records WHERE "type" IN :types AND (subject_agent IN :subs OR named_agent IN :subs)')
    params: dict[str, Any] = {"types": kinds, "subs": subjects, "lim": int(limit)}
    binds = [bindparam("types", expanding=True), bindparam("subs", expanding=True)]
    if created_from is not None:
        sql += " AND created_at >= :cfrom"
        params["cfrom"] = db_ts(created_from)
        binds.append(bindparam("cfrom", type_=DateTime()))
    if created_to is not None:
        sql += " AND created_at <= :cto"
        params["cto"] = db_ts(created_to)
        binds.append(bindparam("cto", type_=DateTime()))
    stmt = text(sql + " ORDER BY created_at DESC, id DESC LIMIT :lim").bindparams(*binds).bindparams(**params)
    out: list[ContextRecord] = []
    for r in _rows(db, stmt, "context_records"):
        payload = parse_json(r.payload)
        out.append(ContextRecord(
            id=int(r.id), type=str(r[1] or "").lower(), subject_agent=_as_str(r.subject_agent),
            payload=payload if isinstance(payload, dict) else {}, created_by=_as_str(r.created_by),
            created_at=to_utc(r.created_at), named_agent=_as_str(r.named_agent), valid_from=to_utc(r.valid_from),
            valid_to=to_utc(r.valid_to),
        ))
    return out
