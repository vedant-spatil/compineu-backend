"""Response playbooks (plan section 9, T9). `run_playbooks` is called by the workflow's finalize step after an analyst
approves a case with playbooks chosen (Bhavya's _finalize, from DecisionIn.playbooks).

    PB1  suspend the agent's credential   agents.credential_enabled = False (the portal answers 403 from the next call)
    PB2  disable the partner key           partner_keys.enabled = False (the partner API answers 403)
    PB6  preserve evidence                 the case bundle to S3 Object Lock via app.services.evidence.preserve_evidence
    PB7  notify                            notify_admins

Every playbook writes write_event(case_id, "playbook", "PBx", {result, approver, reason, ...}). A failing playbook is
rolled back and recorded as {result: "error", error}; it is never raised, so the case still finishes. PB6 never fakes
the S3 write: without EVIDENCE_BUCKET, or when S3 refuses, it records the error. The access events in the bundle leave
out `labels` (ground truth for scoring only).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models
from app.services import evidence
from app.services.audit import write_event
from app.services.cache import invalidate
from app.services.errors import describe_error
from app.services.notify import notify_admins

log = logging.getLogger(__name__)

# Run in this order whatever order they were chosen in: containment first, evidence next, the notification last so it
# can say what was done.
ORDER = ("PB1", "PB2", "PB6", "PB7")
EVIDENCE_EVENT_COLUMNS = ("id", "ts", "actor_id", "actor_type", "action", "resource_type", "resource_id",
                         "policyholder_id", "tier", "records", "outcome", "channel", "ip", "device", "city",
                         "country", "session_id", "detail")


def _case(db: Session, case_id: int) -> models.Case:
    case = db.get(models.Case, case_id)
    if case is None:
        raise LookupError(f"case {case_id} not found")
    return case


def pb1_suspend_agent(db: Session, case_id: int, **_: Any) -> dict[str, Any]:
    case = _case(db, case_id)
    agent = db.get(models.Agent, case.account_id)
    if agent is None:
        return {"result": "not_applicable", "subject": case.account_id}
    already = not agent.credential_enabled
    agent.credential_enabled = False
    db.commit()
    return {"result": "done", "subject": agent.agent_id, "credential_enabled": False, "already_disabled": already}


def pb2_disable_partner_key(db: Session, case_id: int, **_: Any) -> dict[str, Any]:
    case = _case(db, case_id)
    key = db.get(models.PartnerKey, case.account_id)
    if key is None:
        return {"result": "not_applicable", "subject": case.account_id}
    already = not key.enabled
    key.enabled = False
    db.commit()
    return {"result": "done", "subject": key.key_id, "enabled": False, "already_disabled": already}


def evidence_bundle(db: Session, case_id: int) -> dict[str, Any]:
    """The case's audit timeline, the access events its alert cites (txn_ids), the latest report and the decision."""
    case = _case(db, case_id)
    alert = db.get(models.Alert, case.alert_id)
    txn_ids = [int(i) for i in ((alert.raw_json or {}).get("txn_ids", []) if alert else [])]
    timeline = [
        {"id": e.id, "node": e.node, "kind": e.kind, "payload": e.payload_json, "at": e.created_at}
        for e in db.execute(select(models.CaseEvent).where(models.CaseEvent.case_id == case_id)
                            .order_by(models.CaseEvent.id)).scalars()
    ]
    table = models.AccessEvent.__table__
    cited = [dict(row) for row in db.execute(
        select(*(table.c[c] for c in EVIDENCE_EVENT_COLUMNS)).where(table.c.id.in_(txn_ids)).order_by(table.c.ts)
    ).mappings()] if txn_ids else []
    report = db.execute(select(models.SarDraft.body_redacted).where(models.SarDraft.case_id == case_id)
                        .order_by(models.SarDraft.version.desc(), models.SarDraft.id.desc()).limit(1)).scalar()
    decision = db.execute(select(models.Decision).where(models.Decision.case_id == case_id)
                          .order_by(models.Decision.id.desc()).limit(1)).scalar()
    return {
        "case": {"id": case.id, "subject": case.account_id, "status": case.status, "risk_score": case.risk_score},
        "alert": {"id": alert.id, "rules": alert.rules, "risk_score": alert.risk_score,
                  "window": (alert.raw_json or {}).get("window")} if alert else None,
        "cited_event_ids": txn_ids,
        "access_events": cited,
        "timeline": timeline,
        "report": report,
        "decision": {"action": decision.action, "reason": decision.reason, "playbooks": decision.playbooks,
                     "actor_user_id": decision.actor_user_id, "at": decision.created_at} if decision else None,
    }


def _approver(db: Session, actor_user_id: int) -> str:
    user = db.get(models.User, actor_user_id)
    return user.email if user is not None else f"user:{actor_user_id}"


def pb6_preserve_evidence(db: Session, case_id: int, *, actor_user_id: int, reason: str, **_: Any) -> dict[str, Any]:
    bundle = evidence_bundle(db, case_id)
    receipt = evidence.preserve_evidence(db, case_id, bundle, approved_by=_approver(db, actor_user_id), reason=reason)
    return {"result": "done", "key": receipt.get("key"), "version_id": receipt.get("version_id"),
            "retain_until": receipt.get("retain_until"), "events": len(bundle["access_events"])}


def pb7_notify(db: Session, case_id: int, *, done: list[str], **_: Any) -> dict[str, Any]:
    case = _case(db, case_id)
    actions = ", ".join(done) if done else "no containment playbooks"
    notify_admins(db, "incident_actioned", f"Incident on case {case_id} ({case.account_id}) was approved and "
                  f"actioned: {actions}.", link=f"/cases/{case_id}")
    return {"result": "done", "actioned": done}


PLAYBOOKS: dict[str, Callable[..., dict[str, Any]]] = {
    "PB1": pb1_suspend_agent, "PB2": pb2_disable_partner_key, "PB6": pb6_preserve_evidence, "PB7": pb7_notify,
}


def run_playbooks(db: Session, case_id: int, playbooks: list[str], actor_user_id: int,
                  reason: str) -> list[dict[str, Any]]:
    """Run the chosen playbooks for an approved case and audit each one. Returns one result per playbook, in run
    order. Never raises."""
    chosen = list(dict.fromkeys(playbooks or []))
    unknown = [p for p in chosen if p not in PLAYBOOKS]
    results: list[dict[str, Any]] = []
    done: list[str] = []
    for playbook_id in [p for p in ORDER if p in chosen] + unknown:
        try:
            if playbook_id not in PLAYBOOKS:
                raise ValueError(f"unknown playbook {playbook_id}")
            outcome = PLAYBOOKS[playbook_id](db, case_id, actor_user_id=actor_user_id, reason=reason, done=list(done))
        except Exception as exc:  # a failed playbook is recorded; the case still finishes
            log.exception("case %s: playbook %s failed", case_id, playbook_id)
            db.rollback()
            outcome = {"result": "error", "error": describe_error(exc)}
        if outcome.get("result") == "done":
            done.append(playbook_id)
        payload = {**outcome, "approver": actor_user_id, "reason": reason}
        try:
            write_event(db, case_id, "playbook", playbook_id, payload)
        except Exception:  # never raise from here
            log.exception("case %s: could not audit playbook %s", case_id, playbook_id)
            db.rollback()
        results.append({"playbook": playbook_id, **outcome})
    invalidate()
    return results
