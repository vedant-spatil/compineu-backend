"""Agent nodes for the PolicyGuard case workflow. Each takes (db, state) and returns a partial state update.

triage -> load_context -> [gather_evidence | justify | classify] -> join -> route_case -> auto_resolve | report_writer.
The pure logic lives in app/orchestration (corroboration, routing, assembly); these functions read the database, call the
model and write audit rows. RULES DETECT, THE AI EXPLAINS, CODE DECIDES WHETHER PROOF EXISTS, HUMANS APPROVE.

A node never raises. On an error it writes an audit event and returns {"failures": ["<node>: <reason>"]}. Routing treats a
failure of load_context, evidence or justification as blocking, so a data error can never auto-resolve an alert.
Audit rows carry ids and counts, never names and never ticket text. Policyholders appear only as PH_### tokens; the encrypted
token -> name map lives on Case.state and never reaches the model.
"""

import dataclasses
import functools
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import Case, Party, SarDraft, TriageScore
from app.orchestration import assembly
from app.orchestration.corroboration import (
    AUTHORISING_TYPES,
    MAX_OWNERS,
    CorroborationInputs,
    Justification,
    apply_justify_guards,
    build_corroboration_inputs,
    check_corroboration,
    unavailable_corroboration,
)
from app.orchestration.prompts import (
    CLASSIFY_SCHEMA,
    CLASSIFY_SYSTEM,
    JUSTIFY_SCHEMA,
    JUSTIFY_SYSTEM,
    REPORT_SCHEMA,
    REPORT_SYSTEM,
)
from app.orchestration.routing import RouteDecision, route_decision
from app.services import llm, pg_data, pii
from app.services.audit import write_event
from app.services.cache import invalidate
from app.services.errors import describe_error
from app.services.notify import notify_admins
from app.services.pii import encrypt_map

WINDOW_HOURS = 48
BASELINE_DAYS = 30  # history used for an owner's usual daily volume, ending where the window starts
LIGHT_MAX_TOKENS = 1200
HEAVY_MAX_TOKENS = 4000  # the REPORT answer is long; a truncated tool reply is not retried
MAX_PROFILE_LOOKUPS = 12
RECORD_TYPES = ("leave", "ticket", *AUTHORISING_TYPES)
RECORD_LIMIT = 200


# ---- helpers shared by the nodes -----------------------------------------------------------------------------------

def _never_raises(node: str) -> Callable[[Callable[..., dict[str, Any]]], Callable[..., dict[str, Any]]]:
    """Safety net: whatever a node does wrong becomes an audit event and a failure, never an exception."""

    def decorate(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        @functools.wraps(fn)
        def run(db: Session, state: dict[str, Any]) -> dict[str, Any]:
            try:
                return fn(db, state)
            except Exception as exc:  # noqa: BLE001
                return _failed(db, state, node, exc)

        return run

    return decorate


def _failed(db: Session, state: dict[str, Any], node: str, exc: BaseException) -> dict[str, Any]:
    try:
        db.rollback()
        write_event(db, state["case_id"], node, "error", {"error": describe_error(exc)})
    except Exception:  # noqa: BLE001  the audit write itself failed; the failure is still reported to the graph
        pass
    return {"failures": [f"{node}: {type(exc).__name__}"]}


def _allowed_ids(state: dict[str, Any], evidence: dict[str, Any] | None) -> set[int]:
    """Ids a model may cite: the alert's access-event ids (name txn_ids kept) plus every event actually loaded."""
    ids = {int(i) for i in state.get("txn_ids", [])}
    ids.update(int(i) for i in (evidence or {}).get("event_ids", []))
    return ids


def _actor_view(state: dict[str, Any]) -> dict[str, Any]:
    return (state.get("context") or {}).get("actor") or {"actor_id": state["account_id"]}


def _store_identities(db: Session, case_id: int, identities: dict[str, str]) -> None:
    """Keeps the token -> name map encrypted on the case. Only the investigator's view decrypts it; the LLM never sees it."""
    case = db.get(Case, case_id)
    if case is not None:
        case.state = {**(case.state or {}), "identity_map": encrypt_map(identities)}
        db.commit()


# ---- triage (unchanged) --------------------------------------------------------------------------------------------

def _model_score(db: Session, state: dict[str, Any]) -> tuple[float, list[str]] | None:
    """XGBoost triage score for the alert's account on the alert day (plan.md section 24). None if no row."""
    settings = get_settings()
    day = datetime.fromisoformat(state["alert_ts"]).date()
    row = db.execute(
        select(TriageScore.score, TriageScore.reason_codes).where(
            TriageScore.account_id == state["account_id"],
            TriageScore.score_date == day,
            TriageScore.model_version == settings.triage_model_run,
        )
    ).first()
    if row is None:
        return None
    return float(row.score), list(row.reason_codes or [])


def triage(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    score = float(state["risk_score"])
    threshold = settings.triage_threshold
    detail: dict[str, Any] = {"rule_score": score}
    if settings.triage_model == "xgb":
        found = _model_score(db, state)
        if found is None:
            detail["model_missing"] = True  # rule score used instead; recorded in the audit event
        else:
            score, reasons = found
            threshold = settings.triage_score_threshold
            detail.update(model_score=score, model_version=settings.triage_model_run, reason_codes=reasons)
    if score < threshold:
        write_event(db, state["case_id"], "triage", "decision", {"score": score, "threshold": threshold, **detail})
        return {"status": "closed_low_risk"}
    write_event(db, state["case_id"], "triage", "opened",
                {"score": score, "rules": state["alert_rules"], **detail})
    return {"status": "open"}


# ---- load_context --------------------------------------------------------------------------------------------------

def _case_clocks(db: Session, case_id: int, detected: datetime) -> dict[str, str]:
    """CERT-In +6 h and DPDP +72 h from the SIMULATED detection time (alert_ts), stored on Case.state['clocks'] for the
    dashboard. A rerun reuses the stored clocks, so a deadline never restarts."""
    case = db.get(Case, case_id)
    existing = (case.state or {}).get("clocks") if case is not None else None
    clocks = assembly.ensure_clocks(existing, detected)
    if case is not None and not existing:
        case.state = {**(case.state or {}), "clocks": clocks}
        db.commit()
    return clocks


def _actor_type(db: Session, actor: str, profiles: dict[str, pg_data.AgentProfile],
                events: list[pg_data.AccessEvent]) -> str:
    if actor in profiles:
        return "agent"
    if pg_data.fetch_partner_key(db, actor) is not None:
        return "partner_key"
    return events[0].actor_type if events and events[0].actor_type else "unknown"


def _boundary(db: Session, actor: str, actor_type: str) -> set[str] | None:
    """What the actor may touch: an agent's portfolio, a partner key's assigned claims. None when unknown or empty."""
    if actor_type == "agent":
        return pg_data.fetch_portfolio(db, actor) or None
    if actor_type == "partner_key":
        key = pg_data.fetch_partner_key(db, actor)
        return set(key.assigned_claims) if key is not None and key.assigned_claims else None
    return None


def _clean_body(text: str) -> str:
    """Ticket text goes to the model only inside <evidence>. Presidio removes names that are left after tokenising the known
    agent names. If the scrubber is unavailable the text is dropped, never sent."""
    try:
        return pii.scrub_text(text, [])
    except Exception:  # noqa: BLE001
        return ""


def _read_context(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    actor = str(state["account_id"])
    start, end = assembly.window_bounds(state["alert_ts"], WINDOW_HOURS)
    events = pg_data.fetch_events(db, actor, start, end)
    profiles = pg_data.fetch_agents(db, [actor])
    actor_type = _actor_type(db, actor, profiles, events)
    gaps: list[str] = []
    if not events:
        gaps.append("no_access_events_in_window")
    if actor_type == "agent" and actor not in profiles:
        gaps.append("agent_profile_missing")
    boundary = _boundary(db, actor, actor_type)
    if boundary is None:
        gaps.append("scope_unknown_or_empty")
    scope = boundary or set()

    owners_of: dict[str, list[str]] = {}
    records: list[pg_data.ContextRecord] = []
    owner_totals: dict[str, dict[str, int]] = {}
    owners: list[str] = []
    if actor_type == "agent":
        outside = sorted({ev.resource_id for ev in events if ev.outcome == "allowed" and pg_data.is_policyholder_access(ev)
                          and ev.resource_id and ev.resource_id not in scope})
        owners_of = pg_data.fetch_owners(db, outside)
        owners = sorted({o for v in owners_of.values() for o in v if o != actor})
        looked_up = owners[:MAX_PROFILE_LOOKUPS]
        profiles.update(pg_data.fetch_agents(db, looked_up))
        records = pg_data.fetch_context_records(db, [actor, *looked_up], list(RECORD_TYPES), limit=RECORD_LIMIT)
        for owner in owners[:MAX_OWNERS]:  # with more owners the check fails anyway, so no baselines are read
            owner_totals[owner] = pg_data.fetch_daily_record_totals(db, owner, start - timedelta(days=BASELINE_DAYS), start)
        if not records:
            gaps.append("no_context_records")

    # Names are used only to strip them from ticket text. They never go into the state or a prompt.
    manager_ids = {p.manager_id for p in profiles.values() if p.manager_id}
    known = dict(profiles)
    if manager_ids - set(profiles):
        known.update(pg_data.fetch_agents(db, sorted(manager_ids - set(profiles))[:MAX_PROFILE_LOOKUPS]))
    name_to_token = {p.name: f"[{p.agent_id}]" for p in known.values() if p.name}
    clean_records: list[pg_data.ContextRecord] = []
    seen: set[int] = set()
    for rec in records:
        if rec.id in seen:
            continue
        seen.add(rec.id)
        payload = assembly.sanitize_payload(rec.payload, name_to_token)
        if isinstance(payload.get("body"), str):
            payload["body"] = _clean_body(payload["body"])
        clean_records.append(dataclasses.replace(rec, payload=payload))
    nameless = {k: dataclasses.replace(v, name=None) for k, v in profiles.items() if k == actor or k in owners}
    inputs = build_corroboration_inputs(actor, actor_type, events, scope, owners_of, nameless, clean_records, owner_totals)
    me = profiles.get(actor)
    return {
        "actor": {
            "actor_id": actor, "actor_type": actor_type, "hr_status": me.hr_status if me else None,
            "branch": me.branch if me else None, "channel": me.channel if me else None,
            "home_city": me.home_city if me else None, "credential_enabled": me.credential_enabled if me else None,
            "usual_start_hour_ist": me.usual_start_hour if me else None,
            "usual_end_hour_ist": me.usual_end_hour if me else None,
            "manager_id": me.manager_id if me else None, "scope_size": len(scope),
        },
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "corroboration_inputs": inputs.to_dict(),
        "data_gaps": gaps,
        "counts": {"events": len(events), "owners": len(owners), "records": len(clean_records)},
    }


def load_context(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """Actor profile, scope, leave, reporting line and tickets for the window, plus the clocks. If a table is missing or the
    data cannot be read, a failure is recorded and the alert can never auto-resolve."""
    case_id = state["case_id"]
    try:
        clocks = _case_clocks(db, case_id, assembly.window_bounds(state["alert_ts"], 0)[0])
    except Exception as exc:  # noqa: BLE001  an unreadable alert_ts or a failed case update
        return _failed(db, state, "load_context", exc)
    try:
        ctx = _read_context(db, state)
    except pg_data.PgDataError as exc:
        write_event(db, case_id, "load_context", "error", {"table": exc.table, "error": exc.kind})
        return {"clocks": clocks, "context": {"corroboration_inputs": None, "data_gaps": [f"{exc.table}_unavailable"]},
                "failures": [f"load_context: {exc.table} unavailable"]}
    except Exception as exc:  # noqa: BLE001  any other failure also fails safe
        return {**_failed(db, state, "load_context", exc), "clocks": clocks,
                "context": {"corroboration_inputs": None, "data_gaps": ["context_error"]}}
    try:
        write_event(db, case_id, "load_context", "done", {
            **ctx["counts"], "data_gaps": ctx["data_gaps"], "actor_type": ctx["actor"]["actor_type"],
            "detected_at": clocks["detected_at"]})
    except Exception as exc:  # noqa: BLE001
        return {**_failed(db, state, "load_context", exc), "clocks": clocks, "context": ctx}
    return {"clocks": clocks, "context": ctx}


# ---- evidence ------------------------------------------------------------------------------------------------------

class NoEvidenceError(RuntimeError):
    """The actor has no access events in the window."""


def _fetch_evidence(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    actor = str(state["account_id"])
    start, end = assembly.window_bounds(state["alert_ts"], WINDOW_HOURS)
    events = pg_data.fetch_events(db, actor, start, end)
    if not events:
        raise NoEvidenceError("no access events for the actor in the window")
    actor_type = ((state.get("context") or {}).get("actor") or {}).get("actor_type") or events[0].actor_type
    return assembly.build_evidence(events, _boundary(db, actor, actor_type), state.get("txn_ids", []))


def gather_evidence(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """Counts, tiers, exports and a capped timeline for the window. Every number is computed by code."""
    case_id = state["case_id"]
    try:
        evidence = _fetch_evidence(db, state)
    except pg_data.PgDataError as exc:
        write_event(db, case_id, "evidence", "error", {"table": exc.table, "error": exc.kind})
        return {"failures": [f"evidence: {exc.table} unavailable"]}
    except NoEvidenceError as exc:
        write_event(db, case_id, "evidence", "error", {"error": str(exc)})
        return {"failures": ["evidence: no access events"]}
    except Exception as exc:  # noqa: BLE001
        return _failed(db, state, "evidence", exc)
    try:
        write_event(db, case_id, "evidence", "done", {
            "event_count": evidence["event_count"], "out_of_scope_records": evidence["out_of_scope"]["records"],
            "export_rows": evidence["export"]["rows"], "truncated": evidence["truncated"]})
    except Exception as exc:  # noqa: BLE001
        return _failed(db, state, "evidence", exc)
    return {"evidence": evidence}


# ---- justification -------------------------------------------------------------------------------------------------

def justify_with_llm(db: Session, user: str) -> dict[str, Any]:
    """One light-model call with the JUSTIFY schema. Shared with the golden set's --live mode."""
    return llm.complete_json(
        db,
        model=get_settings().llm_model_light,
        system=JUSTIFY_SYSTEM,
        user=user,
        schema_name="justify",
        schema=JUSTIFY_SCHEMA,
        max_completion_tokens=LIGHT_MAX_TOKENS,
    )


@_never_raises("justification")
def justify(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """check_corroboration runs in code first. The model then explains (JUSTIFY schema), and apply_justify_guards makes sure
    it cannot turn a failed check into a justified verdict. Only agents get a model call."""
    case_id = state["case_id"]
    raw = (state.get("context") or {}).get("corroboration_inputs")
    if not raw:
        corro = unavailable_corroboration()
        just = apply_justify_guards(None, corro, set())
        write_event(db, case_id, "justification", "skipped_llm", {"reason": "context unavailable"})
        return {"justification": {**just.to_dict(), "corroboration": corro.to_dict()}}
    inputs = CorroborationInputs.from_dict(raw)
    corro = check_corroboration(inputs)
    fetched = {r.id for r in inputs.records}
    new_failures: list[str] = []
    if inputs.actor_type != "agent":
        just = Justification(verdict="inconclusive", gate_reasons=["llm_skipped_not_agent"])
        write_event(db, case_id, "justification", "skipped_llm", {"reason": "actor is not an agent"})
    else:
        out: dict[str, Any] | None
        try:
            out = justify_with_llm(db, assembly.build_justify_user(inputs, corro))
        except Exception as exc:  # noqa: BLE001  LlmError or anything else: the verdict becomes inconclusive
            db.rollback()
            write_event(db, case_id, "justification", "error", {"error": describe_error(exc)})
            new_failures.append("justification: llm failed")
            out = None
        just = apply_justify_guards(out, corro, fetched)
    write_event(db, case_id, "justification", "done", {
        "verdict": just.verdict, "llm_verdict": just.llm_verdict, "corroboration_ok": corro.ok,
        "failed_checks": corro.failed_checks, "gate_reasons": just.gate_reasons,
        "supporting_record_ids": just.supporting_record_ids, "dropped_ids": just.dropped_ids,
    })
    update: dict[str, Any] = {"justification": {**just.to_dict(), "corroboration": corro.to_dict()}}
    if new_failures:
        update["failures"] = new_failures
    return update


# ---- classify ------------------------------------------------------------------------------------------------------

def _corroboration_view(state: dict[str, Any]) -> tuple[bool | None, list[str]]:
    """(ok, failed_checks) of the code check on the loaded context; (None, []) when the context is not available."""
    raw = (state.get("context") or {}).get("corroboration_inputs")
    if not raw:
        return None, []
    try:
        corro = check_corroboration(CorroborationInputs.from_dict(raw))
    except Exception:  # noqa: BLE001
        return None, []
    return corro.ok, list(corro.failed_checks)


@_never_raises("classify")
def classify(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """Scenario label and ATT&CK ids from the evidence. This branch runs beside gather_evidence, so it builds the evidence
    view itself. Cited ids are filtered to the allowed set, with a dropped_ids count."""
    case_id = state["case_id"]
    try:
        evidence = _fetch_evidence(db, state)
    except pg_data.PgDataError as exc:
        write_event(db, case_id, "classify", "error", {"table": exc.table, "error": exc.kind})
        return {"failures": [f"classify: {exc.table} unavailable"]}
    except NoEvidenceError as exc:
        write_event(db, case_id, "classify", "error", {"error": str(exc)})
        return {"failures": ["classify: no access events"]}
    try:
        out = llm.complete_json(
            db,
            model=get_settings().llm_model_light,
            system=CLASSIFY_SYSTEM,
            user=assembly.build_classify_user(evidence, state.get("alert_rules", []), _actor_view(state)),
            schema_name="classify",
            schema=CLASSIFY_SCHEMA,
            max_completion_tokens=LIGHT_MAX_TOKENS,
        )
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        write_event(db, case_id, "classify", "error", {"error": describe_error(exc)})
        return {"failures": ["classify: llm failed"]}
    cls = assembly.normalize_classification(out, _allowed_ids(state, evidence))
    # The verdict does not exist yet (this branch runs beside justification), so rule (c) is applied again in route_case.
    ok, failed = _corroboration_view(state)
    cls = assembly.apply_scenario_floor(cls, state.get("alert_rules", []), corroboration_ok=ok, failed_checks=failed,
                                        risk_score=state.get("risk_score"))
    write_event(db, case_id, "classify", "done", {
        "scenario": cls["scenario"], "scenario_source": cls["scenario_source"], "model_scenario": cls["model_scenario"],
        "floor_reason": cls["floor_reason"], "cited": len(cls["cited_event_ids"]), "dropped_ids": cls["dropped_ids"]})
    return {"classification": cls}


# ---- route ---------------------------------------------------------------------------------------------------------

@_never_raises("route")
def route_case(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """Medium + justified + corroborated + no hard signal -> auto_resolve. Anything else continues to a human. An error in
    the decision itself means 'investigate'."""
    score = float(state.get("risk_score", 1.0))
    try:
        decision = route_decision(score, state.get("alert_rules", []), state.get("justification"),
                                  state.get("failures", []))
    except Exception:  # noqa: BLE001  never raise from routing; the safe answer is a human
        decision = RouteDecision("investigate", "medium", ("routing error",), ("route_error",))
    payload: dict[str, Any] = {**decision.to_dict(), "score": score}
    update: dict[str, Any] = {"route": decision.to_dict()}
    cls = state.get("classification")
    if cls:  # the verdict is known now: scenario rule (c), and the rest again on the same inputs
        try:
            just = state.get("justification") or {}
            corro = just.get("corroboration")
            final = assembly.apply_scenario_floor(
                cls, state.get("alert_rules", []), corroboration_ok=(bool(corro.get("ok")) if corro else None),
                failed_checks=(corro or {}).get("failed_checks") or [], verdict=just.get("verdict"), risk_score=score)
            if (final["scenario"], final["scenario_source"]) != (cls.get("scenario"), cls.get("scenario_source")):
                update["classification"] = final
                payload["scenario_floor"] = {k: final[k] for k in ("scenario", "scenario_source", "model_scenario", "floor_reason")}
        except Exception:  # noqa: BLE001  a label problem never changes the route
            pass
    write_event(db, state["case_id"], "route", "decision", payload)
    return update


# ---- the report (report_writer and auto_resolve) -------------------------------------------------------------------

def _policyholder_identities(db: Session, evidence: dict[str, Any] | None) -> dict[str, str]:
    """PH_### token -> policyholder name, for the tokens that appear in the evidence. Names stay out of state and prompts."""
    token_to_ph: dict[str, str] = dict((evidence or {}).get("policyholder_tokens") or {})
    if not token_to_ph:
        return {}
    names = {p.account_id: p.name for p in db.execute(
        select(Party).where(Party.account_id.in_(list(token_to_ph.values())))).scalars()}
    return {tok: names[ph] for tok, ph in token_to_ph.items() if ph in names}


def _agent_names(db: Session, state: dict[str, Any]) -> list[str]:
    """Names of the agents involved (actor, owners, managers), used only to scrub the finished report. Best effort."""
    inputs = (state.get("context") or {}).get("corroboration_inputs") or {}
    ids = {str(state["account_id"])}
    for key, profile in (inputs.get("profiles") or {}).items():
        ids.add(str(key))
        if profile.get("manager_id"):
            ids.add(str(profile["manager_id"]))
    try:
        return [p.name for p in pg_data.fetch_agents(db, sorted(ids)[:MAX_PROFILE_LOOKUPS * 2]).values() if p.name]
    except pg_data.PgDataError:
        return []


def _build_and_store_report(db: Session, state: dict[str, Any], llm_out: dict[str, Any] | None,
                            new_failures: list[str]) -> tuple[dict[str, Any], dict[str, Any], int]:
    """assemble (code overwrites every number, clock, id and label), scrub every string, store as a new SarDraft version.
    Fails closed: an unscrubbed report is never stored (the exception is raised to the caller)."""
    case_id = state["case_id"]
    evidence = state.get("evidence")
    identities = _policyholder_identities(db, evidence)
    if identities:
        _store_identities(db, case_id, identities)
    names = [*identities.values(), *_agent_names(db, state)]
    report, meta = assembly.assemble_report_ex(
        llm_out, agent_id=str(state["account_id"]), evidence=evidence, justification=state.get("justification"),
        classification=state.get("classification"), clocks=state.get("clocks") or {},
        allowed_ids=_allowed_ids(state, evidence), failures=[*state.get("failures", []), *new_failures],
        risk_score=state.get("risk_score"), route=state.get("route"), alert_rules=state.get("alert_rules") or [])
    report = pii.scrub_obj(report, names, skip_keys=assembly.SCRUB_SKIP_KEYS)
    version = (db.execute(select(func.count()).select_from(SarDraft).where(SarDraft.case_id == case_id)).scalar_one()) + 1
    db.add(SarDraft(case_id=case_id, version=version, body_redacted=report))
    db.commit()
    return report, meta, version


@_never_raises("report_writer")
def report_writer(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """Incident report, CERT-In draft and DPDP intimation draft (REPORT schema), tokens only. The heavy model writes the
    words; code overwrites counts, clocks, ids and labels, filters ids and scrubs every string. The report is stored in
    sar_drafts.body_redacted, so GET /api/cases/{id}/sar serves it unchanged."""
    case_id = state["case_id"]
    evidence = state.get("evidence")
    new_failures: list[str] = []
    llm_out: dict[str, Any] | None = None
    if evidence is None:
        write_event(db, case_id, "report_writer", "skipped_llm", {"reason": "no evidence"})
    else:
        user = assembly.build_report_user(evidence, state.get("justification"), state.get("classification"),
                                          _actor_view(state), state.get("alert_rules", []), state["alert_ts"],
                                          state.get("failures", []))
        try:
            llm_out = llm.complete_json(
                db,
                model=get_settings().llm_model_heavy,
                system=REPORT_SYSTEM,
                user=user,
                schema_name="incident_report",
                schema=REPORT_SCHEMA,
                max_completion_tokens=HEAVY_MAX_TOKENS,
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            write_event(db, case_id, "report_writer", "error", {"error": describe_error(exc)})
            new_failures.append("report_writer: llm failed")
    try:
        report, meta, version = _build_and_store_report(db, state, llm_out, new_failures)
    except Exception as exc:  # noqa: BLE001  a reviewer must still get a report: build one without the model's words
        if llm_out is None:
            raise
        db.rollback()
        write_event(db, case_id, "report_writer", "error", {"error": describe_error(exc), "stage": "assemble"})
        new_failures.append("report_writer: narrative discarded")
        report, meta, version = _build_and_store_report(db, state, None, new_failures)
    write_event(db, case_id, "report_writer", "done", {
        "timeline_items": len(report["timeline"]), "cited": len(report["cited_event_ids"]),
        "dropped_ids": meta["dropped_ids"], "sar_version": version, "narrative_source": meta["narrative_source"]})
    update: dict[str, Any] = {"incident_report": report, "sar_draft": report}
    if new_failures:
        update["failures"] = new_failures
    return update


# ---- auto_resolve --------------------------------------------------------------------------------------------------

def _supporting_records(state: dict[str, Any], ids: list[int]) -> list[dict[str, Any]]:
    """id, type and the readable reference (payload.ref, e.g. LV-221) of the records the proof rests on."""
    records = ((state.get("context") or {}).get("corroboration_inputs") or {}).get("records") or []
    by_id = {r.get("id"): r for r in records if isinstance(r, dict)}
    out: list[dict[str, Any]] = []
    for rid in ids:
        rec = by_id.get(rid)
        if rec is not None:
            out.append({"id": rid, "type": rec.get("type"), "ref": (rec.get("payload") or {}).get("ref")})
    return out


@_never_raises("auto_resolve")
def auto_resolve(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    """A medium alert with proof in the records (decided in code by route_case). The case stays visible: the code-only report
    and the audit event say why it was closed, in plain language, with the record references."""
    case_id = state["case_id"]
    just = state.get("justification") or {}
    corro = just.get("corroboration") or {}
    update: dict[str, Any] = {"status": "auto_resolved"}
    try:
        report, meta, version = _build_and_store_report(db, state, None, [])
        update.update(incident_report=report, sar_draft=report)
    except Exception as exc:  # noqa: BLE001  the reasons are still in the audit event below
        db.rollback()
        write_event(db, case_id, "auto_resolve", "error", {"stage": "report", "error": describe_error(exc)})
        update["failures"] = ["auto_resolve: report failed"]
        version = None
    ids = sorted({*(corro.get("supporting_record_ids") or []), *(just.get("supporting_record_ids") or [])})
    records = _supporting_records(state, [i for i in ids if isinstance(i, int)])
    refs = [r["ref"] for r in records if r.get("ref")]
    reasons = list(corro.get("reasons") or [])
    summary = ("Medium alert closed automatically. Verdict: " + str(just.get("verdict")) + ". "
               + (f"Supported by {', '.join(refs)}. " if refs else "") + " ".join(reasons))
    case = db.get(Case, case_id)
    if case is not None:
        case.status = "auto_resolved"
        case.closed_at = func.now()
        db.commit()
    write_event(db, case_id, "auto_resolve", "dismissed", {
        "summary": summary[:600], "verdict": just.get("verdict"), "llm_verdict": just.get("llm_verdict"),
        "score": state.get("risk_score"), "reasons": reasons, "supporting_record_ids": ids, "supporting_refs": refs,
        "supporting_records": records, "report_version": version})
    notify_admins(db, "incident_auto_resolved", f"Case {case_id} was closed automatically after code checks.",
                  link=f"/cases/{case_id}")
    invalidate()
    return update
