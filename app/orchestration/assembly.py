"""Pure builders for the case workflow: clocks, evidence, prompt text, classification and the final report.

No database, no model, no wall clock unless a time is passed in. The node wrappers in app/agents/agents.py call these, and
so does the offline golden set. Prompt text is built with json.dumps(sort_keys=True) and contains no wall-clock value and no
case id, so llm_cache hits across reruns. Nothing here puts a person's name into a prompt, the state or the report.
"""

import json
import math
from collections.abc import Collection, Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from app.orchestration.controls import CONTROL_IDS, PLAYBOOK_IDS
from app.orchestration.corroboration import Corroboration, CorroborationInputs
from app.orchestration.prompts import ATTACK_TECHNIQUE_RE, SCENARIOS
from app.orchestration.routing import INCIDENT_THRESHOLD, signal_id
from app.services.pg_data import AccessEvent, is_policyholder_access, percentile, to_utc
from app.services.pii import redact_indian_ids, replace_names

DRAFT_NOTICE = "DRAFT - requires DPO review. DPDP-aligned readiness, not a compliance claim."
CERT_IN_HOURS = 6
DPDP_HOURS = 72
CERT_IN_LABEL = "CERT-In 6-hour report"
DPDP_LABEL = "DPDP-aligned readiness (Rule 7, in force from 13 May 2027)"

MAX_TIMELINE = 12
MAX_CITATIONS = 10
MAX_TOKENIZED_POLICYHOLDERS = 10
TOP_EVENTS = 15
TEXT_LIMIT = 600
MAX_EVENT_IDS = 5000
MAX_PROMPT_RECORDS = 20

PAYLOAD_KEYS = ("ref", "ticket_id", "author_role", "manager_id_at_creation", "status", "scope")

# Keys whose values are ids, enums, numbers, times or code-written text. pii.scrub_obj leaves them alone, so an event id, an
# agent id or a clock value can never be altered by Presidio or by the Aadhaar pattern. Model-written text (title, summary,
# timeline.what, the two drafts, open_questions, justification.reasoning and missing_evidence) is NOT listed: it is scrubbed.
SCRUB_SKIP_KEYS = frozenset({
    "event_id", "ts", "detected_at", "severity", "scenario", "actor", "agent_id", "clocks", "controls_failed",
    "recommended_playbooks", "attack_techniques", "draft_notice", "impact", "cited_event_ids", "verdict", "llm_verdict",
    "gate_reasons", "corroboration", "supporting_record_ids", "closes_incident",
})

# alert score (0..100) -> severity label, computed in code
SEVERITY_BANDS = ((80, "Critical"), (60, "High"), (40, "Medium"))

BLOCKING_NOTES = {
    "load_context": "Context records (leave, tickets, transfers) could not be loaded, so corroboration was not possible.",
    "evidence": "Access events could not be loaded, so counts and the timeline are unavailable.",
    "justification": "The AI justification step failed; the verdict is inconclusive.",
    "classify": "The scenario classification step failed.",
    "report_writer": "The AI narrative step failed; this report was assembled by code only.",
}


# ---- clocks and windows --------------------------------------------------------------------------------------------

def zulu(value: Any) -> str:
    """datetime or ISO string -> 'YYYY-MM-DDTHH:MM:SSZ' (UTC). '' when it cannot be read."""
    dt = to_utc(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt is not None else ""


def compute_clocks(detected_at: datetime) -> dict[str, str]:
    """CERT-In 6 hours and DPDP 72 hours from the detection time. Always computed in code, never by the model."""
    start = to_utc(detected_at)
    if start is None:
        raise ValueError("detected_at must be a datetime")
    return {
        "detected_at": zulu(start),
        "cert_in_due": zulu(start + timedelta(hours=CERT_IN_HOURS)),
        "dpdp_due": zulu(start + timedelta(hours=DPDP_HOURS)),
        "dpdp_label": DPDP_LABEL,
        "cert_in_label": CERT_IN_LABEL,
    }


def ensure_clocks(existing: Mapping[str, Any] | None, now: datetime) -> dict[str, str]:
    """Reuse the clocks already stored on the case so a rerun does not reset the detection time."""
    if existing and all(k in existing for k in ("detected_at", "cert_in_due", "dpdp_due")):
        return {str(k): str(v) for k, v in existing.items()}
    return compute_clocks(now)


def window_bounds(alert_ts: str, hours: int = 48) -> tuple[datetime, datetime]:
    centre = to_utc(alert_ts)
    if centre is None:
        raise ValueError("alert_ts is not an ISO timestamp")
    delta = timedelta(hours=hours)
    return centre - delta, centre + delta


# ---- small helpers -------------------------------------------------------------------------------------------------

def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _text(value: Any, limit: int = TEXT_LIMIT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)


def filter_ids(ids: Iterable[Any], allowed: Collection[int]) -> tuple[list[int], int]:
    """Keeps integer ids that are in the allowed set (once each, in order). Returns (kept, dropped). bool is not an int here."""
    kept: list[int] = []
    dropped = 0
    for i in ids or []:
        if isinstance(i, int) and not isinstance(i, bool) and i in allowed:
            if i not in kept:
                kept.append(i)
        else:
            dropped += 1
    return kept, dropped


def valid_techniques(items: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for item in items or []:
        if isinstance(item, str) and ATTACK_TECHNIQUE_RE.match(item.strip()) and item.strip() not in out:
            out.append(item.strip())
    return out


def assign_policyholder_tokens(ordered_policyholder_ids: Sequence[str], limit: int = MAX_TOKENIZED_POLICYHOLDERS) -> dict[str, str]:
    """policyholder id -> PH_001, PH_002 ... for the first `limit` distinct ids. The others are only ever counted."""
    out: dict[str, str] = {}
    for ph in ordered_policyholder_ids:
        if ph and ph not in out and len(out) < limit:
            out[ph] = f"PH_{len(out) + 1:03d}"
    return out


def sanitize_payload(payload: Mapping[str, Any], name_to_token: Mapping[str, str]) -> dict[str, Any]:
    """The only parts of a record payload that may reach state or a prompt. Names become tokens, PAN and Aadhaar are
    redacted, free text is cut to 600 characters. Everything not listed is dropped."""
    out: dict[str, Any] = {}
    for key in PAYLOAD_KEYS:
        value = payload.get(key)
        if isinstance(value, (str, int, float, bool)):
            out[key] = value
    listed = payload.get("policyholder_ids", payload.get("policyholders"))
    if isinstance(listed, list):
        out["policyholder_count"] = len(listed)
    body = payload.get("body")
    if isinstance(body, str):
        out["body"] = redact_indian_ids(replace_names(body, name_to_token))[:TEXT_LIMIT]
    return out


# ---- evidence ------------------------------------------------------------------------------------------------------

def build_evidence(events: Sequence[AccessEvent], boundary: Collection[str] | None,
                   txn_ids: Collection[int]) -> dict[str, Any]:
    """Counts and a capped timeline from the actor's events. boundary is the portfolio (or a key's assigned claims); None
    means it is unknown, and then every allowed read counts as outside scope. All numbers are computed here, in code.

    Exports are counted apart (rows exported). Reads are allowed policyholder or claim reads. tier_counts are the records
    read outside the boundary, by tier."""
    boundary_known = boundary is not None
    inside_events = inside_records = out_events = out_records = 0
    out_policyholders: set[str] = set()
    tiers = {"T1": 0, "T2": 0, "T3": 0}
    actions: dict[str, int] = {}
    export_ids: list[int] = []
    export_rows = 0
    denied = 0
    records_total = 0

    def inside(ev: AccessEvent) -> bool:
        return boundary_known and (ev.resource_id or "") in boundary  # type: ignore[operator]

    for ev in events:
        if ev.outcome != "allowed":
            denied += 1
            continue
        records_total += ev.records
        actions[ev.action] = actions.get(ev.action, 0) + 1
        if ev.action == "export":
            export_ids.append(ev.id)
            export_rows += ev.records
        elif is_policyholder_access(ev):
            if inside(ev):
                inside_events += 1
                inside_records += ev.records
            else:
                out_events += 1
                out_records += ev.records
                if ev.resource_id:
                    out_policyholders.add(ev.resource_id)
                if ev.tier is not None:
                    tiers[f"T{ev.tier}"] += ev.records

    def story(ev: AccessEvent) -> int:
        """0 for what the alert is about (an export, or an allowed read outside the boundary), 1 for everything else."""
        return 0 if ev.action == "export" or (ev.outcome == "allowed" and is_policyholder_access(ev) and not inside(ev)) else 1

    # The timeline must show the attack, not the oldest events of the window: the story first (the export has the most
    # records, then the reads in time order), then the rest by records.
    ranked = sorted(events, key=lambda e: (story(e), -e.records, e.ts, e.id))[:TOP_EVENTS]
    tokens = assign_policyholder_tokens([e.resource_id or "" for e in ranked if is_policyholder_access(e)])
    top = [{
        "event_id": e.id, "ts": e.ts.isoformat(), "action": e.action, "resource_type": e.resource_type,
        "records": e.records, "tier": f"T{e.tier}" if e.tier else None, "outcome": e.outcome,
        "in_scope": (inside(e) if is_policyholder_access(e) else None),
        "policyholder_token": tokens.get(e.resource_id or "") if is_policyholder_access(e) else None,
    } for e in ranked]

    ids = {e.id for e in events[:MAX_EVENT_IDS]} | {e["event_id"] for e in top}
    return {
        "actor_id": events[0].actor_id if events else None,
        "event_count": len(events),
        "first_ts": min(e.ts for e in events).isoformat() if events else None,
        "last_ts": max(e.ts for e in events).isoformat() if events else None,
        "records_total": records_total,
        "in_scope": {"events": inside_events, "records": inside_records},
        "out_of_scope": {"events": out_events, "records": out_records, "distinct_policyholders": len(out_policyholders)},
        "tier_counts": tiers,
        "actions": dict(sorted(actions.items())),
        "export": {"events": len(export_ids), "rows": export_rows, "event_ids": export_ids[:50]},
        "denied": denied,
        "top_events": top,
        "policyholder_tokens": {tok: ph for ph, tok in tokens.items()},  # ids stay in state; names never do
        "event_ids": sorted(ids),
        "truncated": len(events) > len(top),
        "boundary_known": boundary_known,
        "txn_ids_in_alert": len(list(txn_ids)),
    }


# ---- prompt text ---------------------------------------------------------------------------------------------------

def _record_view(rec: Mapping[str, Any]) -> dict[str, Any]:
    return {k: rec.get(k) for k in ("id", "type", "subject_agent", "named_agent", "created_by", "created_at",
                                    "valid_from", "valid_to", "payload")}


def build_justify_user(inputs: CorroborationInputs, corroboration: Corroboration) -> str:
    """Trusted facts first (computed by code), then the record text inside <evidence>. The record text is untrusted."""
    data = inputs.to_dict()
    history: dict[str, Any] = {}
    for owner, totals in sorted(inputs.owner_daily_totals.items()):
        p95 = percentile(list(totals.values()), 0.95)
        history[owner] = {"history_days": len(totals), "p95_daily_records": None if p95 is None else round(p95, 1)}
    trusted = {
        "actor_id": inputs.actor_id,
        "actor_type": inputs.actor_type,
        "code_check": corroboration.to_dict(),
        "facts": {
            "out_of_portfolio_policyholders": inputs.oop_policyholders,
            "records_per_owner": dict(sorted(inputs.owner_counts.items())),
            "unowned_policyholders": inputs.unowned_count,
            "max_daily_records_read": inputs.oop_daily_max_records,
            "exports_in_window": inputs.export_count,
            "first_access": data["first_oop_ts"],
            "last_access": data["last_oop_ts"],
        },
        "owner_history": history,
        "line_managers": {k: v.manager_id for k, v in sorted(inputs.profiles.items())},
        "record_ids": sorted(r["id"] for r in data["records"]),
    }
    records = sorted(data["records"], key=lambda r: r["id"])[:MAX_PROMPT_RECORDS]
    return (_dumps(trusted) + "\n<evidence>\n" + _dumps({"records": [_record_view(r) for r in records]})
            + "\n</evidence>")


def _aggregates(evidence: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("event_count", "first_ts", "last_ts", "records_total", "in_scope", "out_of_scope", "tier_counts", "actions",
            "export", "denied", "boundary_known")
    return {k: evidence.get(k) for k in keys}


def build_classify_user(evidence: Mapping[str, Any], alert_rules: Sequence[str], actor: Mapping[str, Any]) -> str:
    return _dumps({
        "actor": dict(actor),
        "alert_rules": list(alert_rules),
        "aggregates": _aggregates(evidence),
        "top_events": evidence.get("top_events", []),
        "allowed_scenarios": SCENARIOS,
    })


def build_report_user(evidence: Mapping[str, Any], justification: Mapping[str, Any] | None,
                      classification: Mapping[str, Any] | None, actor: Mapping[str, Any], alert_rules: Sequence[str],
                      alert_ts: str, failures: Sequence[str]) -> str:
    """No clocks, no case id, no names. Policyholders appear only as PH_### tokens inside top_events."""
    just = justification or {}
    corro = just.get("corroboration") or {}
    cls = classification or {}
    return _dumps({
        "actor": dict(actor),
        "alert": {"rules": list(alert_rules), "time": alert_ts},
        "aggregates": _aggregates(evidence),
        "top_events": evidence.get("top_events", []),
        "justification": {"verdict": just.get("verdict"), "failed_checks": corro.get("failed_checks", []),
                          "reasons": corro.get("reasons", [])},
        "classification": {"scenario": cls.get("scenario"), "attack_techniques": cls.get("attack_techniques", [])},
        "step_failures": sorted({str(f).split(":", 1)[0] for f in failures}),
        "allowed_playbooks": list(PLAYBOOK_IDS),
        "allowed_controls": list(CONTROL_IDS),
        "max_citations": MAX_CITATIONS,
        "max_timeline": MAX_TIMELINE,
    })


# ---- model output normalisation ------------------------------------------------------------------------------------

def normalize_classification(llm_out: Mapping[str, Any] | None, allowed_ids: Collection[int]) -> dict[str, Any]:
    """Validates the CLASSIFY answer in code. An unknown scenario becomes None (never silently 'benign_exception')."""
    out = llm_out or {}
    scenario = out.get("scenario") if out.get("scenario") in SCENARIOS else None
    confidence = out.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence):
        confidence = 0.0
    cited, dropped = filter_ids(out.get("cited_event_ids") or [], allowed_ids)
    return {
        "scenario": scenario,
        "attack_techniques": valid_techniques(out.get("attack_techniques") or []),
        "cited_event_ids": cited[:MAX_CITATIONS],
        "confidence": max(0.0, min(1.0, float(confidence))),
        "dropped_ids": dropped,
    }


# ---- scenario floor ------------------------------------------------------------------------------------------------
# The model's scenario label is shown on screen (report.scenario). Real runs had the light model call the S1 bad night
# "negligent" and the forged ticket "benign_exception", so code derives a floor from the signals and the checks.

SOFT_SCENARIOS = frozenset({"benign_exception", "negligent"})
FORGERY_CHECKS = frozenset({"record_authored_by_actor_or_owner", "ticket_not_by_line_manager"})
INSIDER_SIGNALS = frozenset({"A3", "A4"})
PARTNER_SIGNALS = frozenset({"P1", "P2", "P3"})


def scenario_floor(model_scenario: str | None, alert_rules: Iterable[Any], *, corroboration_ok: bool | None,
                   failed_checks: Iterable[str] = (), verdict: str | None = None,
                   risk_score: float | None = None) -> tuple[str | None, str, str]:
    """(scenario, source, reason). source is "model" (label kept, reason "") or "code_floor". In order:
    (a) I1 -> compromised_account; P1/P2/P3 -> compromised_partner.
    (b) corroboration failed, the model said benign_exception or negligent, and there is an export (A3) or unusual-context (A4)
        signal, a forged-evidence check, or a risk of 0.60 or more -> malicious_insider.
    (c) corroboration ok and the final verdict justified -> benign_exception.
    (d) otherwise the model's label stands. A model label never lowers what (a) or (b) derive."""
    signals = {signal_id(r) for r in alert_rules or []}
    label = model_scenario if model_scenario in SCENARIOS else None

    def floor(value: str, reason: str) -> tuple[str | None, str, str]:
        return (value, "model", "") if value == label else (value, "code_floor", reason)

    if "I1" in signals:
        return floor("compromised_account", "signal I1: the identity should be inactive")
    if signals & PARTNER_SIGNALS:
        return floor("compromised_partner", f"partner signal {'/'.join(sorted(signals & PARTNER_SIGNALS))}")
    if corroboration_ok is False and label in SOFT_SCENARIOS:
        why = ([f"signal {s}" for s in sorted(signals & INSIDER_SIGNALS)]
               + [f"check {c}" for c in sorted(set(failed_checks or ()) & FORGERY_CHECKS)]
               + ([f"risk {float(risk_score):.2f} >= {INCIDENT_THRESHOLD:.2f}"]
                  if risk_score is not None and float(risk_score) >= INCIDENT_THRESHOLD - 1e-9 else []))
        if why:
            return floor("malicious_insider", "corroboration failed and " + ", ".join(why))
    if corroboration_ok is True and verdict == "justified":
        return floor("benign_exception", "corroborated by records in code and the verdict is justified")
    return label, "model", ""


def apply_scenario_floor(cls: Mapping[str, Any], alert_rules: Iterable[Any], *, corroboration_ok: bool | None,
                         failed_checks: Iterable[str] = (), verdict: str | None = None,
                         risk_score: float | None = None) -> dict[str, Any]:
    """The classification with `scenario` replaced by the code floor where one applies. Keeps the model's own label in
    `model_scenario` (so the call can be repeated once the verdict is known) and adds `scenario_source` and `floor_reason`."""
    model_label = cls.get("model_scenario", cls.get("scenario"))
    scenario, source, reason = scenario_floor(model_label, alert_rules, corroboration_ok=corroboration_ok,
                                              failed_checks=failed_checks, verdict=verdict, risk_score=risk_score)
    return {**cls, "scenario": scenario, "model_scenario": model_label, "scenario_source": source, "floor_reason": reason}



# ---- the report ----------------------------------------------------------------------------------------------------
# The stored JSON has exactly the keys of docs/samples/incident_report.sample.json (the frontend contract, src/api/report.ts).

def severity_for(score_100: int) -> str:
    for floor, label in SEVERITY_BANDS:
        if score_100 >= floor:
            return label
    return "Low"


def _justification_block(just: Mapping[str, Any] | None, route: Mapping[str, Any] | None) -> dict[str, Any]:
    j = just or {}
    corro = j.get("corroboration") or {}
    missing = j.get("missing_evidence")
    return {
        "verdict": j.get("verdict") or "inconclusive",
        "llm_verdict": j.get("llm_verdict"),
        "reasoning": j.get("reasoning") if isinstance(j.get("reasoning"), str) else "",
        "supporting_record_ids": [i for i in (j.get("supporting_record_ids") or [])
                                  if isinstance(i, int) and not isinstance(i, bool)],
        "missing_evidence": [m for m in missing if isinstance(m, str)] if isinstance(missing, list) else [],
        "corroboration": {
            "ok": bool(corro.get("ok")),
            "failed_checks": list(corro.get("failed_checks") or ([] if j else ["context_unavailable"])),
            "reasons": list(corro.get("reasons") or []),
        },
        "gate_reasons": list(j.get("gate_reasons") or []),
        "closes_incident": bool(route and route.get("action") == "auto_resolve"),
    }


def _ordered_unique(items: Iterable[Any], allowed: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for item in items or []:
        if isinstance(item, str) and item in allowed and item not in seen:
            seen.append(item)
    return seen


def _as_section(value: Any, first_key: str) -> Mapping[str, Any]:
    """A nested draft section as a mapping. The heavy model sometimes returns the object as a JSON string; decode it. Plain
    text that is not JSON becomes the section's first field. Anything else gives an empty section."""
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {first_key: value}
        return parsed if isinstance(parsed, Mapping) else {first_key: value}
    return {}

# Which insurer control an incident breaks, decided in code from the signals that fired (never by the model: it sees the
# control ids only and named controls the evidence did not support, such as the audit trail or human approval, which
# are PolicyGuard's own safeguards and are never "broken" by an incident).
SIGNAL_CONTROLS = {"A1": "C-PORTFOLIO", "P1": "C-PORTFOLIO", "A3": "C-EXPORT", "I1": "C-INACTIVE"}


def controls_from_signals(alert_rules: Sequence[Any] | None, route: Mapping[str, Any] | None = None) -> list[str]:
    """Controls the incident broke. A medium alert auto-resolved as a justified cover broke nothing."""
    if route and route.get("action") == "auto_resolve":
        return []
    out: list[str] = []
    for rule in alert_rules or []:
        control = SIGNAL_CONTROLS.get(signal_id(rule))
        if control and control not in out:
            out.append(control)
    return out


def assemble_report_ex(llm_out: Mapping[str, Any] | None, *, agent_id: str, evidence: Mapping[str, Any] | None,
                       justification: Mapping[str, Any] | None, classification: Mapping[str, Any] | None,
                       clocks: Mapping[str, str], allowed_ids: Collection[int], failures: Sequence[str],
                       risk_score: float | None = None,
                       route: Mapping[str, Any] | None = None,
                       alert_rules: Sequence[Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (report, meta). The model's words are kept, but every number, clock, id, score and label is overwritten or
    filtered by code afterwards. With llm_out None (no evidence, or the call failed) a code-only report is built.
    risk_score is the alert's 0..1 score; route is the RouteDecision dict (it sets justification.closes_incident).
    meta = {dropped_ids, narrative_source}: bookkeeping for the audit trail, not part of the report."""
    ev = evidence or {}
    llm = llm_out or {}
    out_scope = ev.get("out_of_scope") or {}
    tiers = ev.get("tier_counts") or {}
    export = ev.get("export") or {}
    cls = classification or {}
    top_events = [e for e in (ev.get("top_events") or []) if isinstance(e, Mapping) and isinstance(e.get("event_id"), int)]
    ts_of = {e["event_id"]: zulu(e.get("ts")) for e in top_events}

    def code_timeline() -> list[dict[str, Any]]:
        ordered = sorted(top_events, key=lambda e: (e.get("ts") or "", e["event_id"]))
        return [{"event_id": e["event_id"], "ts": zulu(e.get("ts")),
                 "what": f"{e.get('action')} of {e.get('records')} record(s), outcome {e.get('outcome')}"}
                for e in ordered[:MAX_TIMELINE]]

    timeline: list[dict[str, Any]] = []
    dropped = 0
    if llm_out is not None:
        raw_timeline = llm.get("timeline")
        for item in raw_timeline if isinstance(raw_timeline, list) else []:
            eid = item.get("event_id") if isinstance(item, Mapping) else None
            # Only ids whose time is known (top_events) are kept, so every timeline row has a real ts.
            if (isinstance(eid, int) and not isinstance(eid, bool) and eid in allowed_ids and eid in ts_of
                    and len(timeline) < MAX_TIMELINE):
                timeline.append({"event_id": eid, "ts": ts_of[eid], "what": _text(item.get("what"), 300)})
            else:
                dropped += 1
    if not timeline:
        timeline = code_timeline()

    cited, cls_dropped = filter_ids(cls.get("cited_event_ids") or [], allowed_ids)
    for item in timeline:
        if item["event_id"] not in cited:
            cited.append(item["event_id"])

    raw_questions = llm.get("open_questions")
    questions = [q[:300] for q in raw_questions if isinstance(q, str)] if isinstance(raw_questions, list) else []
    for node in sorted({str(f).split(":", 1)[0].strip() for f in failures}):
        if node in BLOCKING_NOTES and BLOCKING_NOTES[node] not in questions:
            questions.append(BLOCKING_NOTES[node])
    if evidence is not None and not ev.get("boundary_known", True):
        questions.append("The actor's authorised scope could not be loaded, so every allowed read was counted as outside scope.")
    if evidence is None:
        questions.append("No access-event evidence could be loaded for this actor and window.")

    cert = llm.get("cert_in_draft")
    dpdp = llm.get("dpdp_intimation_draft")
    stub = "DRAFT - requires DPO review. Not generated; see open_questions." if llm_out is None else ""

    def section(raw: Any, keys: Sequence[str], first: str) -> dict[str, str]:
        source = _as_section(raw, first)
        return {k: (_text(source.get(k)) or (stub if k == first else "")) for k in keys}

    records = _int(out_scope.get("records"))
    score_100 = max(0, min(100, int(round(float(risk_score) * 100)))) if isinstance(risk_score, (int, float)) else 0
    facts = (f"{_int(ev.get('event_count'))} access events by {agent_id}, {records} records read outside the authorised "
             f"scope, {_int(export.get('rows'))} rows exported.")
    reasons = (((justification or {}).get("corroboration") or {}).get("reasons") or [])
    if route and route.get("action") == "auto_resolve":  # a closed medium alert: say why, not "AI unavailable"
        summary_fallback = "Closed automatically by code checks. " + " ".join(reasons[:1]) + " Facts: " + facts
    elif llm_out is not None or evidence is not None:
        summary_fallback = "AI narrative unavailable. Code-computed facts: " + facts
    else:
        summary_fallback = "AI narrative unavailable and no evidence could be loaded."

    report: dict[str, Any] = {
        "title": _text(llm.get("title"), 200) or f"Out-of-scope access by {agent_id}",
        "summary": _text(llm.get("summary")) or summary_fallback,
        "detected_at": zulu(clocks.get("detected_at")),
        "risk_score": score_100,
        "severity": severity_for(score_100),
        "scenario": cls.get("scenario") or "unclassified",
        "attack_techniques": valid_techniques(cls.get("attack_techniques") or []),
        "cited_event_ids": cited[:MAX_CITATIONS],
        "timeline": timeline,
        "impact": {
            "records": records,
            "rows_exported": _int(export.get("rows")),
            "policyholders": _int(out_scope.get("distinct_policyholders")),
            "outside_portfolio_records": records,
            "tiers": {"T1": _int(tiers.get("T1")), "T2": _int(tiers.get("T2")), "T3": _int(tiers.get("T3"))},
        },
        "justification": _justification_block(justification, route),
        "recommended_playbooks": _ordered_unique(llm.get("recommended_playbooks"), PLAYBOOK_IDS),
        # With the alert's signals known (the workflow passes them), code decides; otherwise the model's picks, filtered.
        "controls_failed": (controls_from_signals(alert_rules, route) if alert_rules is not None
                            else _ordered_unique(llm.get("controls_failed"), CONTROL_IDS)),
        "cert_in_draft": section(cert, ("summary", "incident_type", "systems_affected", "timeline_summary",
                                         "actions_taken"), "summary"),
        "dpdp_intimation_draft": section(dpdp, ("nature", "extent", "timing", "location", "likely_impact"), "nature"),
        "open_questions": questions,
        "actor": agent_id,
        "clocks": dict(clocks),
        "draft_notice": DRAFT_NOTICE,
    }
    meta = {"dropped_ids": dropped + cls_dropped, "narrative_source": "llm" if llm_out is not None else "code_only"}
    return report, meta


def assemble_report(llm_out: Mapping[str, Any] | None, **kwargs: Any) -> dict[str, Any]:
    """assemble_report_ex without the meta. See there for the arguments."""
    return assemble_report_ex(llm_out, **kwargs)[0]
