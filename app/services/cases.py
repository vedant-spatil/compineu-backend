"""Start, run and resume case workflows. The graph runs in a background thread; the API returns at once.

Each run is one LangGraph thread. The first run uses the case ID as its thread (as before). A rerun after a failure
uses a new thread, "<case_id>:<attempt>", so the failed checkpoint is not reused.
"""

import logging
from typing import Any

from langgraph.types import Command
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import Alert, Case, CaseAccount, CaseAlert
from app.orchestration.graph import get_graph
from app.services.agentcore import invoke_case
from app.services.audit import write_event
from app.services.cache import invalidate
from app.services.errors import describe_error
from app.services.telemetry import timed

log = logging.getLogger(__name__)

# Hard stop on graph steps per run. The workflow is a DAG (no cycles), so a normal run
# takes about 9 steps. A higher count means a bug, so LangGraph raises instead of looping.
RECURSION_LIMIT = 20

# A case in one of these statuses is the actor's active case; at most one per actor (index uq_cases_account_active).
ACTIVE_STATUSES = ("open", "awaiting_review")
# Only these can be rerun (the /cases/{id}/rerun route and detection's escalation).
RERUNNABLE_STATUSES = ("failed", "awaiting_review")
# Follow-up reruns one run_case thread may start for escalations that arrived while it ran (see run_case_with_followups).
MAX_FOLLOWUP_RERUNS = 5


class RerunRefused(Exception):
    """The case cannot be rerun now: it is not failed or awaiting review, or reopening it would give the actor a second
    active case (uq_cases_account_active). The rerun route answers 409; detection reports "unchanged"."""


def thread_id(case_id: int, attempt: int = 0) -> str:
    return str(case_id) if attempt == 0 else f"{case_id}:{attempt}"


def _attempt(case_id: int) -> int:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        case = db.get(Case, case_id)
        return int((case.state or {}).get("attempt", 0)) if case is not None else 0


def _clear_members_changed(case_id: int) -> None:
    """A workflow that starts has the case's current members, so the "rerun needed" flag no longer applies."""
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        case = db.get(Case, case_id)
        if case is not None and (case.state or {}).get("members_changed"):
            case.state = {k: v for k, v in case.state.items() if k != "members_changed"}
            db.commit()


def active_case_for(db: Session, account_id: str) -> Case | None:
    """The account's one active case (open or awaiting_review), or None. Same condition as uq_cases_account_active."""
    return db.execute(
        select(Case).where(Case.account_id == account_id, Case.status.in_(ACTIVE_STATUSES))
    ).scalars().first()


def start_case(db: Session, alert: Alert) -> Case:
    case = Case(alert_id=alert.id, account_id=alert.account_id, status="open",
                risk_score=alert.risk_score, state={})
    db.add(case)
    db.flush()
    # Membership rows, so case grouping sees this case (plan: case grouping, step 1).
    db.add(CaseAccount(case_id=case.id, account_id=alert.account_id, role="subject", active=True))
    db.add(CaseAlert(case_id=case.id, alert_id=alert.id, active=True))
    db.commit()
    write_event(db, case.id, "ingest_alert", "start", {"alert_id": alert.id})
    invalidate()
    return case


def run_case(case_id: int, alert_id: int, account_id: str, alert_ts: str, rules: list[str], risk: float,
             txn_ids: list[int], attempt: int = 0) -> None:
    """Background task entry point: runs the case where CASE_RUNNER says. Errors are logged and recorded as a failed case."""
    _clear_members_changed(case_id)
    if get_settings().case_runner == "agentcore":
        _run_on_agentcore({
            "case_id": case_id, "alert_id": alert_id, "account_id": account_id, "alert_ts": alert_ts,
            "rules": list(rules), "risk": risk, "txn_ids": list(txn_ids), "attempt": attempt,
        })
        return
    run_case_local(case_id, alert_id, account_id, alert_ts, rules, risk, txn_ids, attempt)


def _run_on_agentcore(payload: dict[str, Any]) -> None:
    try:
        invoke_case(payload)
    except Exception as exc:  # any failure is recorded on the case, not raised to the caller
        log.exception("case %s AgentCore run failed", payload["case_id"])
        _mark_failed(payload["case_id"], describe_error(exc))
    finally:
        invalidate()


def run_case_local(case_id: int, alert_id: int, account_id: str, alert_ts: str, rules: list[str], risk: float,
                   txn_ids: list[int], attempt: int = 0) -> None:
    """The LangGraph workflow in this process. The AgentCore agent calls this too, with CASE_RUNNER=local."""
    graph = get_graph()
    config = {"configurable": {"thread_id": thread_id(case_id, attempt)}, "recursion_limit": RECURSION_LIMIT}
    initial: dict[str, Any] = {
        "case_id": case_id,
        "alert_id": alert_id,
        "account_id": account_id,
        "alert_ts": alert_ts,
        "alert_rules": rules,
        "risk_score": risk,
        "txn_ids": txn_ids,
        "failures": [],
        "status": "open",
    }
    try:
        with timed("case_run", case_id=case_id, attempt=attempt, mode="start"):
            graph.invoke(initial, config)
    except Exception as exc:
        log.exception("case %s run failed", case_id)
        _mark_failed(case_id, describe_error(exc))
    finally:
        invalidate()


def prepare_rerun(db: Session, case_id: int, *, reason: str | None = None,
                  by_user_id: int | None = None) -> dict[str, Any]:
    """Move a failed or awaiting_review case back to open for its next attempt and return run_case's arguments, with
    the alert's current txn_ids. Clears case.state["rerun_pending"] (this rerun sees the latest evidence).

    The case row is locked and its status re-read first, so the rerun route, detection and a finishing run thread
    cannot start two attempts at once. Raises RerunRefused, or LookupError if the case or its alert is gone."""
    case = db.execute(
        select(Case).where(Case.id == case_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if case is None:
        raise LookupError("case not found")
    if case.status not in RERUNNABLE_STATUSES:
        db.rollback()
        raise RerunRefused(f"case is {case.status}; only failed cases or cases awaiting review can be rerun")
    alert = db.get(Alert, case.alert_id)
    if alert is None:
        db.rollback()
        raise LookupError("alert not found")
    attempt = int((case.state or {}).get("attempt", 0)) + 1
    args = {
        "case_id": case.id, "alert_id": alert.id, "account_id": alert.account_id, "alert_ts": alert.ts.isoformat(),
        "rules": list(alert.rules or []), "risk": alert.risk_score,
        "txn_ids": [int(i) for i in (alert.raw_json or {}).get("txn_ids", [])], "attempt": attempt,
    }
    case.state = {**{k: v for k, v in (case.state or {}).items() if k != "rerun_pending"}, "attempt": attempt}
    case.status = "open"
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise RerunRefused("the actor already has another active case") from exc
    payload: dict[str, Any] = {"attempt": attempt, "by_user_id": by_user_id}
    if reason:
        payload["reason"] = reason
    write_event(db, case_id, "workflow", "rerun", payload)
    invalidate()
    return args


def take_pending_rerun(case_id: int) -> dict[str, Any] | None:
    """If detection flagged this case (rerun_pending) while its workflow ran and the case is now awaiting_review, clear
    the flag and prepare the rerun. Returns run_case's arguments, or None when there is nothing to do."""
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        case = db.execute(select(Case).where(Case.id == case_id).with_for_update()).scalar_one_or_none()
        if case is None or case.status != "awaiting_review" or not (case.state or {}).get("rerun_pending"):
            return None
        try:
            return prepare_rerun(db, case_id, reason="rerun_pending")
        except (RerunRefused, LookupError) as exc:
            log.warning("case %s: pending rerun not started: %s", case_id, exc)
            return None


def run_case_with_followups(case_id: int, alert_id: int, account_id: str, alert_ts: str, rules: list[str],
                            risk: float, txn_ids: list[int], attempt: int = 0) -> None:
    """run_case, then the pending-rerun check (T7). Detection sets rerun_pending when the risk escalates while the
    workflow is still running; the replay may stop calling detection soon after (S1 lasts 38 real seconds), so the
    thread that ran the case reruns it when it stops at awaiting_review, with the alert's current txn_ids, until the
    flag stays clear."""
    run_case(case_id, alert_id, account_id, alert_ts, rules, risk, txn_ids, attempt)
    for _ in range(MAX_FOLLOWUP_RERUNS):
        follow = take_pending_rerun(case_id)
        if follow is None:
            return
        run_case(**follow)
    log.warning("case %s: still escalating after %d follow-up reruns; detection's next call takes over",
                case_id, MAX_FOLLOWUP_RERUNS)


def resume_case(case_id: int, decision: dict[str, Any]) -> None:
    graph = get_graph()
    config = {"configurable": {"thread_id": thread_id(case_id, _attempt(case_id))},
              "recursion_limit": RECURSION_LIMIT}
    try:
        with timed("case_run", case_id=case_id, mode="resume"):
            graph.invoke(Command(resume=decision), config)
    finally:
        invalidate()


def _mark_failed(case_id: int, error: str) -> None:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        case = db.get(Case, case_id)
        if case is not None and case.status not in ("approved", "closed"):
            case.status = "failed"
            db.commit()
        write_event(db, case_id, "graph", "error", {"error": error[:500]})
    invalidate()
