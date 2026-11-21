"""PolicyGuard detectors (plan section 4): one actor's access events in a 60-minute window -> signals and Risk.

Pure Python: no database, no pandas. app.services.detection (T7) loads the rows, builds the inputs below and calls
`detect()`. Built here: A1, A3, A4 (T5); I1, P1, P2, P3, A2 (T6). Not built: A5, I3, P4.

Ground truth stays out: `AccessEvent` has no `labels` field, so no detector can read it (CLAUDE.md rule 3). This module
must not import app.ingest.alerts (it needs the Unix-only `resource` module).

Definitions used by every detector:
- Only `allowed` events touched data. A1, A3, P1 and I1 count only those, so the 403s an agent or key gets after PB1
  or PB2 cannot open a new incident. A4, P2 and P3 look at every event (refusals and 404s are part of the pattern).
- Records touched (`n_records`) = distinct records opened (view, api_get), or the largest export's row count if that
  is larger. An export carries only a row count, so this is the lower bound of what was touched (S1: 1,840 opened,
  1,200 exported -> 1,840, the plan's value).
- Tier = the highest tier among the data events (view, api_get, export). Login and search are T3 with 0 records.
- Agent usual hours are IST; `ts` is naive UTC, so the hours check adds 5:30.
- A2 compares like with like: each baseline hour is counted with the same records-touched rule as the window.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from itertools import pairwise
from statistics import median
from typing import Any

from app.services import risk as risk_fn

WINDOW = timedelta(minutes=60)
IST_OFFSET = timedelta(hours=5, minutes=30)
MAX_EVENT_IDS = 200
DETAIL_LIST_CAP = 5

CONFIDENCE = {"A1": 0.9, "A2": 0.7, "A3": 0.8, "A4": 0.4, "I1": 0.95, "P1": 0.9, "P2": 0.8, "P3": 0.6}
A1_MIN_OUT_OF_SCOPE = 10
A1_ACTIONS = frozenset({"view", "search", "export"})
A3_MIN_EXPORT_ROWS = 200
INACTIVE_HR_STATUSES = frozenset({"suspended", "terminated"})
P2_MIN_FETCHES = 20
P2_SEQUENTIAL_SHARE = 0.8
P2_FAILED_SHARE = 0.3
A2_LOOKBACK = timedelta(days=30)
A2_MIN_Z = 4.0
A2_PEER_MULTIPLE = 3.0
A2_MIN_OWN_DAYS = 7
# Context record types that put a colleague's portfolio in scope. Tickets and leave do not: judging those is the AI's job.
SCOPE_RECORD_TYPES = frozenset({"transfer", "servicing_assignment", "approval"})
DATA_ACTIONS = frozenset({"view", "api_get", "export"})
TIER_RANK = {"T3": 1, "T2": 2, "T1": 3}


def _as_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


# ------------------------------------------------------------------ inputs


@dataclass(frozen=True)
class AccessEvent:
    """One access_events row, without `labels` (ground truth) and without free-form `detail`."""

    id: int
    ts: datetime
    actor_id: str
    actor_type: str
    action: str
    resource_type: str
    resource_id: str
    policyholder_id: str | None = None
    tier: str | None = None
    records: int = 1
    outcome: str = "allowed"
    channel: str = "portal"
    ip: str | None = None
    device: str | None = None
    city: str | None = None
    session_id: str | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> AccessEvent:
        """From an access_events row mapping or a dict. Other keys (labels, detail, country, ...) are dropped."""
        known = {f.name for f in fields(cls)}
        values = {k: row[k] for k in known if k in row}
        values["ts"] = _as_datetime(values["ts"])
        return cls(**values)


@dataclass(frozen=True)
class AgentProfile:
    """The parts of an agents row the detectors use."""

    agent_id: str
    usual_start_hour: int
    usual_end_hour: int
    home_city: str | None
    known_devices: frozenset[str]
    manager_id: str | None = None
    branch: str | None = None
    hr_status: str = "active"
    credential_enabled: bool = True

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> AgentProfile:
        return cls(
            agent_id=row["agent_id"], usual_start_hour=int(row["usual_start_hour"]),
            usual_end_hour=int(row["usual_end_hour"]), home_city=row.get("home_city"),
            known_devices=frozenset(row.get("known_devices") or ()), manager_id=row.get("manager_id"),
            branch=row.get("branch"), hr_status=row.get("hr_status", "active"),
            credential_enabled=bool(row.get("credential_enabled", True)),
        )


@dataclass(frozen=True)
class ContextRecord:
    """A context_records row. Valid from `valid_from` (inclusive) to `valid_to` (exclusive); None is open-ended."""

    type: str
    subject_agent: str | None
    named_agent: str | None
    valid_from: datetime | None = None
    valid_to: datetime | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> ContextRecord:
        return cls(type=row["type"], subject_agent=row.get("subject_agent"), named_agent=row.get("named_agent"),
                   valid_from=_as_datetime(row.get("valid_from")), valid_to=_as_datetime(row.get("valid_to")))

    def valid_at(self, ts: datetime) -> bool:
        return (self.valid_from is None or self.valid_from <= ts) and (self.valid_to is None or ts < self.valid_to)


@dataclass(frozen=True)
class AgentScope:
    """The policyholders an agent may open: its own portfolio and its reports' portfolios (always), plus the
    portfolios that a transfer, servicing assignment or approval naming the agent grants while it is valid."""

    always: frozenset[str]
    grants: tuple[tuple[ContextRecord, frozenset[str]], ...] = ()

    def allows(self, policyholder_id: str, ts: datetime) -> bool:
        if policyholder_id in self.always:
            return True
        return any(policyholder_id in phs and rec.valid_at(ts) for rec, phs in self.grants)


def build_scope(agent_id: str, portfolios: Mapping[str, Iterable[str]], reports: Iterable[str],
                records: Iterable[ContextRecord]) -> AgentScope:
    """`portfolios` maps agent_id -> policyholder ids, at least for the agent, its reports and the subjects of the
    records. `reports` are the agents whose manager_id is this agent. Records of other types, or naming someone else,
    are ignored."""
    always = set(portfolios.get(agent_id, ()))
    for report in reports:
        always.update(portfolios.get(report, ()))
    grants = tuple(
        (rec, frozenset(portfolios.get(rec.subject_agent, ())))
        for rec in records
        if rec.type in SCOPE_RECORD_TYPES and rec.named_agent == agent_id and rec.subject_agent
    )
    return AgentScope(always=frozenset(always), grants=grants)


@dataclass(frozen=True)
class PartnerProfile:
    """A partner_keys row and the claims assigned to it (partner_claim_assignments)."""

    key_id: str
    enabled: bool = True
    known_ips: frozenset[str] = frozenset()
    assigned_claims: frozenset[str] = frozenset()

    @classmethod
    def from_row(cls, row: Mapping[str, Any], assigned_claims: Iterable[str] = ()) -> PartnerProfile:
        return cls(key_id=row["key_id"], enabled=bool(row.get("enabled", True)),
                   known_ips=frozenset(row.get("known_ips") or ()), assigned_claims=frozenset(assigned_claims))


@dataclass(frozen=True)
class Baseline:
    """A2's reference: records touched per active hour, for the actor over the last 30 days and for its branch peers
    over the same period (pooled). `own_days` is how far back the actor's history goes, in IST calendar days from its
    first to its last day with records (a Sunday off does not shorten it; a new hire's 3 days do)."""

    own_hourly: tuple[int, ...] = ()
    own_days: int = 0
    peer_hourly: tuple[int, ...] = ()

    @classmethod
    def from_history(cls, own: Iterable[AccessEvent], peers: Iterable[AccessEvent]) -> Baseline:
        own = list(own)
        days = [(e.ts + IST_OFFSET).date() for e in own if e.outcome == "allowed" and e.action in DATA_ACTIONS]
        span = (max(days) - min(days)).days + 1 if days else 0
        return cls(own_hourly=tuple(hourly_counts(own)), own_days=span, peer_hourly=tuple(hourly_counts(peers)))


def hourly_counts(events: Iterable[AccessEvent]) -> list[int]:
    """Records touched in each (actor, clock hour) that had any, by the same rule as a window (records_and_tier)."""
    buckets: dict[tuple[str, datetime], list[AccessEvent]] = defaultdict(list)
    for e in events:
        buckets[(e.actor_id, e.ts.replace(minute=0, second=0, microsecond=0))].append(e)
    counts = (records_and_tier(group)[0] for group in buckets.values())
    return [c for c in counts if c > 0]


def _percentile(values: Sequence[int], q: float) -> float:
    """Linear interpolation between closest ranks (numpy's default)."""
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q
    low, high = math.floor(rank), math.ceil(rank)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


# ------------------------------------------------------------------ output


@dataclass
class Detection:
    """What one actor's window produced. `signals` maps signal id -> {"confidence", "detail"}; `event_ids` are the
    access_events ids to cite (txn_ids), most relevant first."""

    actor_id: str
    actor_type: str
    window_start: datetime
    window_end: datetime
    signals: dict[str, dict[str, Any]]
    n_records: int
    tier: str | None
    event_ids: list[int]
    risk: float
    band: str

    @property
    def fired(self) -> bool:
        return bool(self.signals)

    @property
    def window(self) -> dict[str, str]:
        """For alert.raw_json["window"] (naive UTC, ISO)."""
        return {"start": self.window_start.isoformat(), "end": self.window_end.isoformat()}


# ------------------------------------------------------------------ detectors


def _ist_hour(ts: datetime) -> int:
    return (ts + IST_OFFSET).hour


def _within_usual_hours(hour: int, start: int, end: int) -> bool:
    """[start, end) in IST hours. start > end is an overnight shift; start == end means any hour."""
    if start == end:
        return True
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def a1_out_of_portfolio(events: Sequence[AccessEvent], scope: AgentScope) -> tuple[dict[str, Any] | None, list[int]]:
    """A1: at least 10 distinct out-of-scope policyholders viewed, searched or exported (allowed) in the window."""
    flagged: list[int] = []
    outside: set[str] = set()
    for e in events:
        if e.outcome == "allowed" and e.action in A1_ACTIONS and e.policyholder_id \
                and not scope.allows(e.policyholder_id, e.ts):
            outside.add(e.policyholder_id)
            flagged.append(e.id)
    if len(outside) < A1_MIN_OUT_OF_SCOPE:
        return None, []
    return {"confidence": CONFIDENCE["A1"], "detail": {"out_of_scope_policyholders": len(outside)}}, flagged


def a3_bulk_export(events: Sequence[AccessEvent]) -> tuple[dict[str, Any] | None, list[int]]:
    """A3: an allowed export of 200+ rows, or any allowed export of T1 data."""
    hits = [e for e in events if e.outcome == "allowed" and e.action == "export"
            and (e.records >= A3_MIN_EXPORT_ROWS or e.tier == "T1")]
    if not hits:
        return None, []
    detail = {"exports": len(hits), "max_rows": max(e.records for e in hits), "t1": any(e.tier == "T1" for e in hits)}
    return {"confidence": CONFIDENCE["A3"], "detail": detail}, [e.id for e in hits]


def a4_unusual_context(events: Sequence[AccessEvent], agent: AgentProfile) -> tuple[dict[str, Any] | None, list[int]]:
    """A4 (fires once): any event outside usual hours (IST), from a device not in known_devices, or from a city other
    than home_city. A missing device or city never counts as new or unusual."""
    off_hours = 0
    devices: set[str] = set()
    cities: set[str] = set()
    flagged: list[int] = []
    for e in events:
        hit = False
        if not _within_usual_hours(_ist_hour(e.ts), agent.usual_start_hour, agent.usual_end_hour):
            off_hours += 1
            hit = True
        if e.device is not None and e.device not in agent.known_devices:
            devices.add(e.device)
            hit = True
        if e.city is not None and agent.home_city is not None and e.city != agent.home_city:
            cities.add(e.city)
            hit = True
        if hit:
            flagged.append(e.id)
    if not flagged:
        return None, []
    detail: dict[str, Any] = {"fired": []}
    if off_hours:
        detail["fired"].append("off_hours")
        detail["off_hours_events"] = off_hours
    if devices:
        detail["fired"].append("new_device")
        detail["new_devices"] = sorted(devices)[:DETAIL_LIST_CAP]
    if cities:
        detail["fired"].append("new_city")
        detail["new_cities"] = sorted(cities)[:DETAIL_LIST_CAP]
    return {"confidence": CONFIDENCE["A4"], "detail": detail}, flagged


def i1_inactive_identity(events: Sequence[AccessEvent], *, agent: AgentProfile | None = None,
                         partner: PartnerProfile | None = None) -> tuple[dict[str, Any] | None, list[int]]:
    """I1 (floor Risk 60): a suspended or terminated agent, or a disabled credential or partner key, with at least one
    allowed event in the window. Refused attempts alone do not fire it: after PB1 or PB2 the 403s must not open new
    incidents."""
    if agent is not None:
        inactive = agent.hr_status in INACTIVE_HR_STATUSES or not agent.credential_enabled
        detail: dict[str, Any] = {"hr_status": agent.hr_status, "credential_enabled": agent.credential_enabled}
    elif partner is not None:
        inactive = not partner.enabled
        detail = {"key_enabled": partner.enabled}
    else:
        return None, []
    allowed = [e.id for e in events if e.outcome == "allowed"]
    if not inactive or not allowed:
        return None, []
    detail["allowed_events"] = len(allowed)
    return {"confidence": CONFIDENCE["I1"], "detail": detail}, allowed


def _claim_fetches(events: Sequence[AccessEvent]) -> list[AccessEvent]:
    return [e for e in events if e.action == "api_get" and e.resource_type == "claim"]


def p1_unassigned_claim(events: Sequence[AccessEvent],
                        partner: PartnerProfile) -> tuple[dict[str, Any] | None, list[int]]:
    """P1: the key was given (allowed) a claim that is not assigned to it."""
    hits = [e for e in _claim_fetches(events) if e.outcome == "allowed" and e.resource_id not in partner.assigned_claims]
    if not hits:
        return None, []
    return {"confidence": CONFIDENCE["P1"], "detail": {"unassigned_claims": len({e.resource_id for e in hits})}}, \
        [e.id for e in hits]


_TRAILING_NUMBER = re.compile(r"(\d+)$")


def p2_enumeration(events: Sequence[AccessEvent]) -> tuple[dict[str, Any] | None, list[int]]:
    """P2: at least 20 claim fetches, and either 80%+ of the sorted numeric claim ids step by 1, or more than 30% of
    the fetches were refused or not found."""
    fetches = _claim_fetches(events)
    if len(fetches) < P2_MIN_FETCHES:
        return None, []
    numbers = sorted({int(m.group(1)) for e in fetches if (m := _TRAILING_NUMBER.search(e.resource_id or ""))})
    steps = [b - a for a, b in pairwise(numbers)]
    sequential = sum(1 for s in steps if s == 1) / len(steps) if steps else 0.0
    failed = sum(1 for e in fetches if e.outcome in ("denied", "not_found")) / len(fetches)
    if sequential < P2_SEQUENTIAL_SHARE and failed <= P2_FAILED_SHARE:
        return None, []
    detail = {"fetches": len(fetches), "sequential_share": round(sequential, 2), "failed_share": round(failed, 2)}
    return {"confidence": CONFIDENCE["P2"], "detail": detail}, [e.id for e in fetches]


def p3_new_origin(events: Sequence[AccessEvent], partner: PartnerProfile) -> tuple[dict[str, Any] | None, list[int]]:
    """P3: a request from an IP the key has not used before (not in known_ips). A missing IP never counts."""
    hits = [e for e in events if e.ip is not None and e.ip not in partner.known_ips]
    if not hits:
        return None, []
    detail = {"new_ips": sorted({e.ip for e in hits})[:DETAIL_LIST_CAP]}
    return {"confidence": CONFIDENCE["P3"], "detail": detail}, [e.id for e in hits]


def a2_volume_spike(records: int, baseline: Baseline) -> dict[str, Any] | None:
    """A2: the window's records touched against the actor's own hours (robust z = (x - median) / (1.4826 * MAD) >= 4,
    with MAD floored at 1 record so a flat history cannot divide by zero) and against its branch peers
    (x > 3 * their hourly p95). With fewer than 7 days of own history, the peer test alone decides; without peer data,
    the own test alone. Neither available: no signal."""
    if records <= 0:
        return None
    detail: dict[str, Any] = {"records": records, "own_days": baseline.own_days}
    own_ok: bool | None = None
    if baseline.own_days >= A2_MIN_OWN_DAYS and baseline.own_hourly:
        mid = median(baseline.own_hourly)
        mad = median(abs(c - mid) for c in baseline.own_hourly)
        z = (records - mid) / (1.4826 * max(mad, 1.0))
        own_ok = z >= A2_MIN_Z
        detail |= {"own_median": mid, "z": round(z, 1)}
    peer_ok: bool | None = None
    if baseline.peer_hourly:
        p95 = _percentile(baseline.peer_hourly, 0.95)
        peer_ok = records > A2_PEER_MULTIPLE * p95
        detail["peer_p95"] = round(p95, 1)
    if own_ok is None and peer_ok is None:
        return None
    fired = (own_ok is not False) and (peer_ok is not False)
    return {"confidence": CONFIDENCE["A2"], "detail": detail} if fired else None


# ------------------------------------------------------------------ entry point


def records_and_tier(events: Sequence[AccessEvent]) -> tuple[int, str | None]:
    """(records touched, highest tier touched) over the allowed data events; see the module docstring."""
    data = [e for e in events if e.outcome == "allowed" and e.action in DATA_ACTIONS]
    opened = {(e.resource_type, e.resource_id) for e in data if e.action != "export"}
    biggest_export = max((e.records for e in data if e.action == "export"), default=0)
    tiers = [e.tier for e in data if e.tier in TIER_RANK]
    tier = max(tiers, key=TIER_RANK.__getitem__) if tiers else None
    return max(len(opened), biggest_export), tier


def detect(actor_id: str, actor_type: str, events: Iterable[AccessEvent], now: datetime, *,
           agent: AgentProfile | None = None, scope: AgentScope | None = None,
           partner: PartnerProfile | None = None, baseline: Baseline | None = None) -> Detection:
    """Run the detectors on `actor_id`'s events in [now - 60 min, now]. Events of other actors or outside the window
    are ignored. Each signal runs only when its input is given: agents need `scope` (A1), `agent` (A4, I1) and
    `baseline` (A2); partner keys need `partner` (P1, P2, P3, I1)."""
    start = now - WINDOW
    window = sorted((e for e in events if e.actor_id == actor_id and start <= e.ts <= now), key=lambda e: (e.ts, e.id))
    n_records, tier = records_and_tier(window)

    # In relevance order for the evidence ids. A2 cites no events of its own (the rest of the window follows).
    checks: list[tuple[str, tuple[dict[str, Any] | None, list[int]]]] = []
    if actor_type == "agent":
        checks.append(("A3", a3_bulk_export(window)))
        if scope is not None:
            checks.append(("A1", a1_out_of_portfolio(window, scope)))
        if agent is not None:
            checks.append(("I1", i1_inactive_identity(window, agent=agent)))
            checks.append(("A4", a4_unusual_context(window, agent)))
        if baseline is not None:
            checks.append(("A2", (a2_volume_spike(n_records, baseline), [])))
    elif actor_type == "partner_key" and partner is not None:
        checks.append(("P1", p1_unassigned_claim(window, partner)))
        checks.append(("I1", i1_inactive_identity(window, partner=partner)))
        checks.append(("P3", p3_new_origin(window, partner)))
        checks.append(("P2", p2_enumeration(window)))
    signals: dict[str, dict[str, Any]] = {}
    cited: list[list[int]] = []
    for signal_id, (found, ids) in checks:
        if found is not None:
            signals[signal_id] = found
            cited.append(ids)

    value, band = risk_fn.score({k: v["confidence"] for k, v in signals.items()}, tier, n_records, actor_type)
    return Detection(actor_id=actor_id, actor_type=actor_type, window_start=start, window_end=now,
                     signals=dict(sorted(signals.items())), n_records=n_records, tier=tier,
                     event_ids=_cite(cited, window) if signals else [], risk=value, band=band)


def _cite(groups: list[list[int]], window: Sequence[AccessEvent]) -> list[int]:
    """Evidence ids, most relevant first: the fired signals' events in order (A3, A1, A4), then the rest of the
    window's data events. At most MAX_EVENT_IDS, no repeats."""
    rest = [e.id for e in window if e.outcome == "allowed" and e.action in DATA_ACTIONS]
    out: list[int] = []
    seen: set[int] = set()
    for group in [*groups, rest]:
        for event_id in group:
            if event_id not in seen:
                seen.add(event_id)
                out.append(event_id)
                if len(out) == MAX_EVENT_IDS:
                    return out
    return out
