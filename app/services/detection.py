"""Detection entry point (T7): `process_actor(actor_id, now)` runs the detectors on one actor's last 60 minutes, upserts
the actor's alert, and opens, updates or escalates the actor's case.

Sumit's replay (app/portal/replay.py) calls it every few seconds per active actor and once at the end, with a simulated
clock that runs ahead of the wall clock. So the function is idempotent, and `now` is the only clock: every time
comparison and `alert.ts` use it. This module never reads the wall clock.

Rules (docs/policyguard/RAGHAV_TASKS.md, T7):
0. Only events after the actor's most recent decided case (approved, closed, auto_resolved; not superseded) count; the
   cutoff is that case's alert.raw_json["window"]["end"]. A decided case whose cited events a reset deleted is ignored.
1. No signals -> "none".
2-3. No active case: a case dismissed (auto_resolved or closed) less than 60 minutes ago blocks a new one unless the new
   band is higher. Otherwise reuse the actor's caseless alert from the last 60 minutes or insert one; band low ->
   "logged", else open a case and run it in a daemon thread -> "opened".
4. Active case: update its alert and risk. Escalate when the band went up or a new signal fired: rerun now if the case
   is awaiting_review, else set rerun_pending for the run thread (cases.run_case_with_followups) -> "escalated".
   A pending flag on a case already awaiting_review is also taken here. Otherwise "unchanged".

The detectors get row mappings without `labels`; is_laundering (ground truth, for scoring only) has its own query here.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import models
from app.ingest import pg_rules
from app.services import cases as case_service
from app.services import risk as risk_fn
from app.services.audit import write_event
from app.services.cache import invalidate

log = logging.getLogger(__name__)

SOURCE_LABEL = "policyguard"
ACTIVE_STATUSES = case_service.ACTIVE_STATUSES
DECIDED_STATUSES = ("approved", "closed", "auto_resolved")
DISMISSED_STATUSES = ("auto_resolved", "closed")
DISMISSAL_HOLD = timedelta(minutes=60)
ALERT_REUSE = timedelta(minutes=60)
EVIDENCE_CHECK_IDS = 50  # a decided case gates detection only while (some of) its first 50 cited events still exist
BAND_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# access_events columns the detectors may see. labels (ground truth) and detail never reach pg_rules.
EVENT_COLUMNS = ("id", "ts", "actor_id", "actor_type", "action", "resource_type", "resource_id", "policyholder_id",
                 "tier", "records", "outcome", "channel", "ip", "device", "city", "session_id")


# ------------------------------------------------------------------ decisions (pure)


def should_escalate(old_band: str, old_rules: set[str] | list[str], new_band: str, new_signals) -> bool:
    """Escalate when the band went up, or a signal fired that the case's alert did not have (S1's export, A3, arrives
    last, when the band is already critical)."""
    return BAND_RANK[new_band] > BAND_RANK[old_band] or bool(set(new_signals) - set(old_rules))


def dismissal_blocks(decided_status: str, decided_band: str, decided_end: datetime | None, new_band: str,
                     now: datetime) -> bool:
    """No repeat case after a dismissal: within 60 minutes of an auto_resolved or closed case's window end, a new case
    opens only for a higher band (S1b can be auto-resolved while most of its reads are still arriving)."""
    return (decided_status in DISMISSED_STATUSES and decided_end is not None and now - decided_end < DISMISSAL_HOLD
            and BAND_RANK[new_band] <= BAND_RANK[decided_band])


def alert_band(alert: Any) -> str:
    raw = alert.raw_json or {}
    return raw.get("band") or risk_fn.band(float(alert.risk_score or 0) * 100)


def window_end(alert: Any) -> datetime | None:
    """The alert's last detection tick (raw_json["window"]["end"]), else its ts."""
    end = ((alert.raw_json or {}).get("window") or {}).get("end")
    return datetime.fromisoformat(end) if end else alert.ts


# ------------------------------------------------------------------ database side


@dataclass
class Inputs:
    actor_type: str
    events: list[pg_rules.AccessEvent]
    agent: pg_rules.AgentProfile | None = None
    scope: pg_rules.AgentScope | None = None
    partner: pg_rules.PartnerProfile | None = None
    baseline: pg_rules.Baseline | None = None


class Store:
    """Everything process_actor reads or writes. Tests use an in-memory fake with the same methods."""

    def __init__(self, db: Session):
        self.db = db

    def last_decided(self, actor_id: str) -> tuple[models.Case, models.Alert] | None:
        row = self.db.execute(
            select(models.Case, models.Alert).join(models.Alert, models.Alert.id == models.Case.alert_id)
            .where(models.Case.account_id == actor_id, models.Case.status.in_(DECIDED_STATUSES))
            .order_by(models.Case.id.desc()).limit(1)
        ).first()
        return (row[0], row[1]) if row else None

    def inputs(self, actor_id: str, cutoff: datetime | None, now: datetime) -> Inputs | None:
        db = self.db
        agent_row = db.execute(select(models.Agent.__table__).where(models.Agent.agent_id == actor_id)).mappings().first()
        if agent_row is not None:
            actor_type = "agent"
        elif db.get(models.PartnerKey, actor_id) is not None:
            actor_type = "partner_key"
        else:
            return None
        table = models.AccessEvent.__table__
        query = select(*(table.c[name] for name in EVENT_COLUMNS)).where(
            table.c.actor_id == actor_id, table.c.ts >= now - pg_rules.WINDOW, table.c.ts <= now)
        if cutoff is not None:
            query = query.where(table.c.ts > cutoff)
        events = [pg_rules.AccessEvent.from_row(row) for row in db.execute(query.order_by(table.c.ts, table.c.id)).mappings()]
        if actor_type != "agent":
            key_row = db.execute(
                select(models.PartnerKey.__table__).where(models.PartnerKey.key_id == actor_id)).mappings().one()
            assigned = db.execute(select(models.PartnerClaimAssignment.claim_id)
                                  .where(models.PartnerClaimAssignment.key_id == actor_id)).scalars()
            return Inputs(actor_type, events, partner=pg_rules.PartnerProfile.from_row(key_row, assigned))
        reports = list(db.execute(select(models.Agent.agent_id).where(models.Agent.manager_id == actor_id)).scalars())
        record_rows = db.execute(
            select(models.ContextRecord.__table__).where(
                models.ContextRecord.named_agent == actor_id,
                models.ContextRecord.type.in_(pg_rules.SCOPE_RECORD_TYPES))
        ).mappings().all()
        records = [pg_rules.ContextRecord.from_row(r) for r in record_rows]
        owners = {actor_id, *reports, *(r.subject_agent for r in records if r.subject_agent)}
        portfolios: dict[str, set[str]] = {}
        for agent_id, policyholder_id in db.execute(
                select(models.Portfolio.agent_id, models.Portfolio.policyholder_id)
                .where(models.Portfolio.agent_id.in_(owners))):
            portfolios.setdefault(agent_id, set()).add(policyholder_id)
        scope = pg_rules.build_scope(actor_id, portfolios, reports, records)
        return Inputs(actor_type, events, pg_rules.AgentProfile.from_row(agent_row), scope,
                      baseline=self.baseline(actor_id, agent_row["branch"], now))

    def baseline(self, actor_id: str, branch: str, now: datetime) -> pg_rules.Baseline:
        """A2's reference: the actor's and its branch peers' allowed data events in the 30 days before the window."""
        end = now - pg_rules.WINDOW
        peers = list(self.db.execute(select(models.Agent.agent_id).where(
            models.Agent.branch == branch, models.Agent.agent_id != actor_id)).scalars())
        table = models.AccessEvent.__table__
        rows = self.db.execute(select(*(table.c[name] for name in EVENT_COLUMNS)).where(
            table.c.actor_id.in_([actor_id, *peers]), table.c.ts >= end - pg_rules.A2_LOOKBACK, table.c.ts < end,
            table.c.outcome == "allowed", table.c.action.in_(pg_rules.DATA_ACTIONS))).mappings()
        history = [pg_rules.AccessEvent.from_row(row) for row in rows]
        return pg_rules.Baseline.from_history((e for e in history if e.actor_id == actor_id),
                                              (e for e in history if e.actor_id != actor_id))

    def active_case(self, actor_id: str) -> models.Case | None:
        """The actor's active case, row-locked until the next commit (serialises with the run thread)."""
        return self.db.execute(
            select(models.Case).where(models.Case.account_id == actor_id, models.Case.status.in_(ACTIVE_STATUSES))
            .with_for_update()
        ).scalars().first()

    def alert(self, alert_id: int) -> models.Alert | None:
        return self.db.get(models.Alert, alert_id)

    def reusable_alert(self, actor_id: str, now: datetime) -> models.Alert | None:
        """The actor's newest PolicyGuard alert from the last 60 minutes that no case uses."""
        return self.db.execute(
            select(models.Alert).where(
                models.Alert.account_id == actor_id, models.Alert.source_label == SOURCE_LABEL,
                models.Alert.ts >= now - ALERT_REUSE, models.Alert.ts <= now,
                ~exists().where(models.Case.alert_id == models.Alert.id))
            .order_by(models.Alert.id.desc()).limit(1)
        ).scalars().first()

    def new_alert(self, now: datetime) -> models.Alert:
        alert = models.Alert(ts=now, source_label=SOURCE_LABEL, source="rules")
        self.db.add(alert)
        return alert

    def is_attack(self, event_ids: list[int]) -> bool:
        """Ground truth for the quality page: any cited event labelled is_attack. Never given to the detectors."""
        if not event_ids:
            return False
        table = models.AccessEvent.__table__
        labels = self.db.execute(select(table.c.labels).where(table.c.id.in_(event_ids))).scalars()
        return any(isinstance(lab, dict) and bool(lab.get("is_attack")) for lab in labels)

    def evidence_exists(self, event_ids: list[int]) -> bool:
        """Whether any of the first 50 cited events still exists. A reset deletes the replayed events."""
        ids = [int(i) for i in event_ids[:EVIDENCE_CHECK_IDS]]
        if not ids:
            return False
        table = models.AccessEvent.__table__
        return bool(self.db.execute(select(exists().where(table.c.id.in_(ids)))).scalar())

    def start_case(self, alert: models.Alert) -> models.Case:
        self.db.flush()
        return case_service.start_case(self.db, alert)

    def prepare_rerun(self, case_id: int, reason: str) -> dict[str, Any]:
        return case_service.prepare_rerun(self.db, case_id, reason=reason)

    def audit(self, case_id: int, kind: str, payload: dict[str, Any]) -> None:
        write_event(self.db, case_id, "detection", kind, payload)  # commits

    def commit(self) -> None:
        self.db.commit()

    def rollback(self) -> None:
        self.db.rollback()


# ------------------------------------------------------------------ entry point


def process_actor(actor_id: str, now: datetime) -> dict[str, Any]:
    """Run detection for one actor at `now` (naive UTC, possibly simulated). Returns
    {"action": none | logged | opened | escalated | unchanged, "alert_id", "case_id", "risk", "band"}."""
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        result, run_args = process(Store(db), actor_id, now)
    if run_args is not None:
        _start_run(run_args)
    if result["action"] != "none":
        invalidate()
    return result


def _start_run(args: dict[str, Any]) -> None:
    threading.Thread(target=case_service.run_case_with_followups, kwargs=args,
                     name=f"case-{args['case_id']}-a{args['attempt']}", daemon=True).start()


def _result(action: str, det: pg_rules.Detection | None = None, alert: Any = None, case: Any = None) -> dict[str, Any]:
    return {"action": action, "alert_id": getattr(alert, "id", None), "case_id": getattr(case, "id", None),
            "risk": det.risk if det else 0.0, "band": det.band if det else "low"}


def _fill_alert(alert: Any, det: pg_rules.Detection, is_attack: bool) -> None:
    """The alert mapping in CLAUDE.md. alert.ts is left alone (set to `now` when the alert is first inserted)."""
    alert.account_id = det.actor_id
    alert.amount = det.n_records
    alert.rules = sorted(det.signals)
    alert.risk_score = det.risk / 100
    alert.is_laundering = is_attack
    alert.raw_json = {"txn_ids": list(det.event_ids), "signals": det.signals, "n_records": det.n_records,
                      "tier": det.tier, "band": det.band, "window": det.window, "actor_type": det.actor_type}


def _run_args(case: Any, alert: Any) -> dict[str, Any]:
    raw = alert.raw_json or {}
    return {"case_id": case.id, "alert_id": alert.id, "account_id": alert.account_id, "alert_ts": alert.ts.isoformat(),
            "rules": list(alert.rules or []), "risk": alert.risk_score,
            "txn_ids": [int(i) for i in raw.get("txn_ids", [])], "attempt": 0}


def _rerun(store: Any, case_id: int, reason: str) -> dict[str, Any] | None:
    try:
        return store.prepare_rerun(case_id, reason)
    except case_service.RerunRefused as exc:
        log.info("case %s: rerun not started: %s", case_id, exc)
        return None


def process(store: Any, actor_id: str, now: datetime) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """The decision logic over `store`. Returns (result, run_case arguments to start, or None)."""
    decided = store.last_decided(actor_id)
    if decided and not store.evidence_exists((decided[1].raw_json or {}).get("txn_ids", [])):
        # A reset deleted that case's events. Its window end is on an earlier replay's clock (up to 58 minutes
        # ahead of real time), so it must not cut off or block the next rehearsal.
        decided = None
    cutoff = window_end(decided[1]) if decided else None
    inputs = store.inputs(actor_id, cutoff, now)
    if inputs is None:  # neither an agent nor a partner key
        return _result("none"), None
    det = pg_rules.detect(actor_id, inputs.actor_type, inputs.events, now, agent=inputs.agent, scope=inputs.scope,
                          partner=inputs.partner, baseline=inputs.baseline)
    if not det.fired:
        return _result("none", det), None

    case = store.active_case(actor_id)
    if case is None:
        if decided and dismissal_blocks(decided[0].status, alert_band(decided[1]), cutoff, det.band, now):
            store.rollback()
            return _result("none", det), None
        alert = store.reusable_alert(actor_id, now) or store.new_alert(now)
        _fill_alert(alert, det, store.is_attack(det.event_ids))
        if det.band == "low":
            store.commit()
            return _result("logged", det, alert), None
        try:
            case = store.start_case(alert)
        except IntegrityError:  # another call opened the actor's case first
            store.rollback()
            return _result("unchanged", det), None
        return _result("opened", det, alert, case), _run_args(case, alert)

    alert = store.alert(case.alert_id)
    old = {"risk": round(float(alert.risk_score or 0) * 100, 1), "band": alert_band(alert),
           "signals": sorted(alert.rules or [])}
    status = case.status  # read under the row lock
    _fill_alert(alert, det, store.is_attack(det.event_ids))
    case.risk_score = det.risk / 100
    if should_escalate(old["band"], old["signals"], det.band, det.signals):
        if status == "open":  # the workflow is still running: its thread reruns when it stops
            case.state = {**(case.state or {}), "rerun_pending": True}
        store.audit(case.id, "risk_escalated", {
            "old": old, "new": {"risk": det.risk, "band": det.band, "signals": sorted(det.signals)},
            "signals": sorted(set(det.signals) - set(old["signals"])),
        })
        if status == "awaiting_review":
            run_args = _rerun(store, case.id, "risk_escalated")
            if run_args is None:
                return _result("unchanged", det, alert, case), None
            return _result("escalated", det, alert, case), run_args
        return _result("escalated", det, alert, case), None
    if status == "awaiting_review" and (case.state or {}).get("rerun_pending"):
        store.commit()
        run_args = _rerun(store, case.id, "rerun_pending")
        if run_args is None:
            return _result("unchanged", det, alert, case), None
        return _result("escalated", det, alert, case), run_args
    store.commit()
    return _result("unchanged", det, alert, case), None
