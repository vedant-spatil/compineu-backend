"""LangGraph workflow per case (PolicyGuard, docs/policyguard/BHAVYA_TASKS.md section 2).

START -> triage --(closed_low_risk)--> close_low -> END
           |
           v
      load_context --+--> evidence       --+
                     +--> justification  --+--> join -> route --(auto_resolve)--> auto_resolve -> END
                     +--> classify       --+                |
                                                            +--(investigate)--> report_writer -> await_human -> finalize -> END

The graph nodes evidence, justification and route share their names with state keys; the LangGraph version pinned here
accepts that (checked at compile time and in a run with the Postgres checkpointer). Functions in app/agents/agents.py are
gather_evidence, justify and route_case. Audit events use the node names evidence, justification and route.
"""

from collections.abc import Callable
from typing import Any

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from psycopg.rows import dict_row
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.agents import agents
from app.config import get_settings
from app.db.models import Case, Decision
from app.db.session import SessionLocal
from app.orchestration.controls import PLAYBOOK_IDS
from app.orchestration.state import CaseState
from app.services.audit import write_event
from app.services.errors import describe_error
from app.services.telemetry import timed


def _node(fn: Callable[[Session, dict[str, Any]], dict[str, Any]]) -> Callable[[CaseState], dict[str, Any]]:
    """Each node gets its own DB session, so parallel branches never share one."""

    def run(state: CaseState) -> dict[str, Any]:
        with timed("node", node=fn.__name__, case_id=state.get("case_id")), SessionLocal() as db:
            return fn(db, dict(state))

    run.__name__ = fn.__name__
    return run


def _join(state: CaseState) -> dict[str, Any]:
    return {}


def _await_human(state: CaseState) -> dict[str, Any]:
    review = {
        "case_id": state["case_id"],
        "report": state.get("incident_report"),
        "route": state.get("route"),
        "failures": state.get("failures", []),
    }
    with SessionLocal() as db:
        case = db.get(Case, state["case_id"])
        if case is not None:
            case.status = "awaiting_review"
            db.commit()
        if review["failures"]:
            # A step failed, so the case is waiting for review without some of its context, evidence or classification.
            # Say so in the audit trail; the investigator decides whether to restart it.
            write_event(db, state["case_id"], "review", "incomplete", {"failures": review["failures"]})
    decision = interrupt(review)  # resumed with Command(resume=decision_dict)
    return {"decision": decision, "status": "awaiting_review"}


def _requested_playbooks(decision: dict[str, Any], action: str) -> list[str]:
    """Playbook ids the approver chose. Only an approval runs playbooks, and only ids that exist are kept."""
    if action != "approve":
        return []
    raw = decision.get("playbooks") or []
    if not isinstance(raw, list):
        return []
    return [p for p in dict.fromkeys(x for x in raw if isinstance(x, str)) if p in PLAYBOOK_IDS]


def _run_playbooks(db: Session, case_id: int, playbooks: list[str], decision: dict[str, Any]) -> None:
    """Raghav's executor (app.services.playbooks.run_playbooks). Imported lazily: until the module is on main, the approved
    ids are only recorded and an audit event says the run was skipped."""
    try:
        from app.services.playbooks import run_playbooks
    except ImportError:
        write_event(db, case_id, "finalize", "playbooks_skipped", {"requested": playbooks})
        return
    try:
        run_playbooks(db, case_id, playbooks, int(decision["actor_user_id"]), decision.get("reason", ""))
    except Exception as exc:  # noqa: BLE001  a failed playbook is recorded, the decision stands
        db.rollback()
        write_event(db, case_id, "finalize", "playbook_error", {"error": describe_error(exc)})


def _finalize(state: CaseState) -> dict[str, Any]:
    decision = state.get("decision") or {}
    action = decision.get("action", "close")
    status = "approved" if action == "approve" else "closed"
    playbooks = _requested_playbooks(decision, action)
    with SessionLocal() as db:
        case = db.get(Case, state["case_id"])
        if case is not None:
            case.status = status
            case.closed_at = func.now()
            db.add(
                Decision(
                    case_id=state["case_id"],
                    action=action,
                    reason=decision.get("reason", ""),
                    typologies=decision.get("typologies", []),
                    playbooks=playbooks,
                    actor_user_id=int(decision["actor_user_id"]),
                )
            )
            db.commit()
        write_event(db, state["case_id"], "finalize", "decision", {"action": action, "playbooks": playbooks})
        if action == "approve" and playbooks:
            _run_playbooks(db, state["case_id"], playbooks, decision)
    return {"status": status}


def _close_low(state: CaseState) -> dict[str, Any]:
    with SessionLocal() as db:
        case = db.get(Case, state["case_id"])
        if case is not None:
            case.status = "closed"
            db.commit()
    return {"status": "closed_low_risk"}


def _after_triage(state: CaseState) -> str:
    return "close_low" if state.get("status") == "closed_low_risk" else "load_context"


def _after_route(state: CaseState) -> str:
    """Only an explicit auto_resolve decision closes the case; a missing or odd route goes to a human."""
    return "auto_resolve" if (state.get("route") or {}).get("action") == "auto_resolve" else "report_writer"


def build_graph(checkpointer: Any):
    g = StateGraph(CaseState)
    g.add_node("triage", _node(agents.triage))
    g.add_node("close_low", _close_low)
    g.add_node("load_context", _node(agents.load_context))
    g.add_node("evidence", _node(agents.gather_evidence))
    g.add_node("justification", _node(agents.justify))
    g.add_node("classify", _node(agents.classify))
    g.add_node("join", _join)
    g.add_node("route", _node(agents.route_case))
    g.add_node("auto_resolve", _node(agents.auto_resolve))
    g.add_node("report_writer", _node(agents.report_writer))
    g.add_node("await_human", _await_human)
    g.add_node("finalize", _finalize)

    g.add_edge(START, "triage")
    g.add_conditional_edges("triage", _after_triage, {"close_low": "close_low", "load_context": "load_context"})
    g.add_edge("close_low", END)
    for branch in ("evidence", "justification", "classify"):
        g.add_edge("load_context", branch)
        g.add_edge(branch, "join")
    g.add_edge("join", "route")
    g.add_conditional_edges("route", _after_route, {"auto_resolve": "auto_resolve", "report_writer": "report_writer"})
    g.add_edge("auto_resolve", END)
    g.add_edge("report_writer", "await_human")
    g.add_edge("await_human", "finalize")
    g.add_edge("finalize", END)
    return g.compile(checkpointer=checkpointer)


_compiled: Any = None


def get_graph() -> Any:
    """Compiled graph with a long-lived Postgres checkpointer (pending cases survive restarts)."""
    global _compiled
    if _compiled is None:
        conn_str = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
        conn = psycopg.connect(conn_str, autocommit=True, prepare_threshold=0, row_factory=dict_row)
        saver = PostgresSaver(conn)
        saver.setup()
        _compiled = build_graph(saver)
    return _compiled


__all__ = ["build_graph", "get_graph", "Command"]
