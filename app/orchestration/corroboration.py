"""Deterministic corroboration (plan section 5) and the guards on the model's justification. Pure: no database, no model.

check_corroboration answers one question in code: do records exist that explain agent X reading the policyholders of
agent(s) Y? The ticket BODY TEXT is never read here. Records follow the 0011 columns: subject_agent = Y (whose
portfolio or leave), named_agent = X (who is authorised), valid_from / valid_to (valid_to exclusive), and the author
is created_by. Nothing in the payload can make a record count: the payload is untrusted. The model may explain the result, but apply_justify_guards makes sure
it cannot turn a failed check into a 'justified' verdict.

Failure codes (failed_checks), in the order they are found:
  not_agent_actor, no_out_of_portfolio_access, unowned_policyholder, too_many_owners, export_in_window,
  no_authorising_record, leave_not_approved_or_not_covering, ticket_not_by_line_manager,
  record_created_after_first_access, record_authored_by_actor_or_owner, record_author_unknown,
  record_scope_too_narrow, owner_profile_missing, owner_baseline_missing, volume_exceeds_owner_p95, context_unavailable
"""

from collections.abc import Collection, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.services.pg_data import (
    AccessEvent,
    AgentProfile,
    ContextRecord,
    is_policyholder_access,
    percentile,
    to_utc,
)

MAX_OWNERS = 3
MIN_BASELINE_DAYS = 3  # fewer days make an owner's p95 too thin to be a proof; the full world gives every cover owner 22+
RECORD_WINDOW = timedelta(hours=48)
AUTHORISING_TYPES = ("transfer", "servicing_assignment", "approval")
VERDICTS = ("justified", "unjustified", "inconclusive")

REASON_TEXT = {
    "not_agent_actor": "The actor is not an agent, so leave and ticket records cannot cover the access.",
    "no_out_of_portfolio_access": "No allowed access outside the authorised scope was found in the window.",
    "unowned_policyholder": "Some policyholders read are in nobody's portfolio, so no colleague can be covering for them.",
    "too_many_owners": f"The policyholders belong to more than {MAX_OWNERS} agents; no single cover arrangement explains that.",
    "export_in_window": "The actor exported data in the window; cover arrangements never justify an export.",
    "no_authorising_record": "No transfer, servicing assignment, approval or manager ticket names this agent for the owner.",
    "leave_not_approved_or_not_covering": "No approved leave of the owner covers the whole access window.",
    "ticket_not_by_line_manager": "The ticket was not written by the owner's line manager.",
    "record_created_after_first_access": "The record was created at or after the first out-of-scope access.",
    "record_authored_by_actor_or_owner": "The record was written by the agent who accessed the data or by its owner.",
    "record_author_unknown": "The record has no author, so independence cannot be shown.",
    "record_scope_too_narrow": "The record does not cover the whole access (period or number of policyholders).",
    "owner_profile_missing": "The owner's HR profile is missing, so the line manager cannot be checked.",
    "owner_baseline_missing": f"The owner has fewer than {MIN_BASELINE_DAYS} days of history to compare volume against.",
    "volume_exceeds_owner_p95": "The volume read in a day is above the owner's own 95th percentile daily volume.",
    "context_unavailable": "Context data could not be loaded, so nothing can be corroborated.",
}


@dataclass
class CorroborationInputs:
    actor_id: str
    actor_type: str  # "agent" | "partner_key" | "iam_role"
    first_oop_ts: datetime | None = None
    last_oop_ts: datetime | None = None
    oop_policyholders: int = 0
    owner_counts: dict[str, int] = field(default_factory=dict)
    unowned_count: int = 0
    oop_daily_max_records: int = 0
    export_count: int = 0
    records: list[ContextRecord] = field(default_factory=list)  # candidate records: naming X, plus the owners' leave
    profiles: dict[str, AgentProfile] = field(default_factory=dict)  # names are NOT stored here (name=None)
    owner_daily_totals: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe (strings, numbers, lists, dicts). Goes into the LangGraph state, so it never carries names."""
        return {
            "actor_id": self.actor_id, "actor_type": self.actor_type,
            "first_oop_ts": self.first_oop_ts.isoformat() if self.first_oop_ts else None,
            "last_oop_ts": self.last_oop_ts.isoformat() if self.last_oop_ts else None,
            "oop_policyholders": self.oop_policyholders, "owner_counts": dict(self.owner_counts),
            "unowned_count": self.unowned_count, "oop_daily_max_records": self.oop_daily_max_records,
            "export_count": self.export_count,
            "records": [{"id": r.id, "type": r.type, "subject_agent": r.subject_agent, "named_agent": r.named_agent,
                         "payload": r.payload, "created_by": r.created_by,
                         "created_at": r.created_at.isoformat() if r.created_at else None,
                         "valid_from": r.valid_from.isoformat() if r.valid_from else None,
                         "valid_to": r.valid_to.isoformat() if r.valid_to else None}
                        for r in self.records],
            "profiles": {k: {**asdict(v), "name": None} for k, v in self.profiles.items()},
            "owner_daily_totals": {k: dict(v) for k, v in self.owner_daily_totals.items()},
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CorroborationInputs":
        records: list[ContextRecord] = []
        for r in d.get("records") or []:
            try:
                payload = r.get("payload")
                records.append(ContextRecord(
                    id=int(r["id"]), type=str(r.get("type") or ""), subject_agent=r.get("subject_agent"),
                    payload=payload if isinstance(payload, dict) else {}, created_by=r.get("created_by"),
                    created_at=to_utc(r.get("created_at")), named_agent=r.get("named_agent"),
                    valid_from=to_utc(r.get("valid_from")), valid_to=to_utc(r.get("valid_to"))))
            except (KeyError, TypeError, ValueError):
                continue  # a malformed record is simply not evidence
        profiles = {k: AgentProfile(**{**v, "agent_id": v.get("agent_id", k),
                                       "known_devices": tuple(v.get("known_devices") or ())})
                    for k, v in (d.get("profiles") or {}).items()}
        return cls(
            actor_id=str(d.get("actor_id", "")), actor_type=str(d.get("actor_type", "")),
            first_oop_ts=to_utc(d.get("first_oop_ts")), last_oop_ts=to_utc(d.get("last_oop_ts")),
            oop_policyholders=int(d.get("oop_policyholders") or 0),
            owner_counts={str(k): int(v) for k, v in (d.get("owner_counts") or {}).items()},
            unowned_count=int(d.get("unowned_count") or 0),
            oop_daily_max_records=int(d.get("oop_daily_max_records") or 0),
            export_count=int(d.get("export_count") or 0), records=records, profiles=profiles,
            owner_daily_totals={str(k): {str(dk): int(dv) for dk, dv in v.items()}
                                for k, v in (d.get("owner_daily_totals") or {}).items()},
        )


@dataclass
class Corroboration:
    ok: bool
    failed_checks: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)  # plain language
    supporting_record_ids: list[int] = field(default_factory=list)  # empty unless ok

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "failed_checks": list(self.failed_checks), "reasons": list(self.reasons),
                "supporting_record_ids": list(self.supporting_record_ids)}


@dataclass
class Justification:
    verdict: str  # final: justified | unjustified | inconclusive
    llm_verdict: str | None = None
    supporting_record_ids: list[int] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    reasoning: str = ""
    gate_reasons: list[str] = field(default_factory=list)
    dropped_ids: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "llm_verdict": self.llm_verdict,
                "supporting_record_ids": list(self.supporting_record_ids),
                "missing_evidence": list(self.missing_evidence), "reasoning": self.reasoning,
                "gate_reasons": list(self.gate_reasons), "dropped_ids": self.dropped_ids}


# ---- building the inputs --------------------------------------------------------------------------------------------

def build_corroboration_inputs(actor_id: str, actor_type: str, events: Sequence[AccessEvent], portfolio: Collection[str],
                               owners_of: Mapping[str, Sequence[str]], profiles: Mapping[str, AgentProfile],
                               records: Sequence[ContextRecord],
                               owner_daily_totals: Mapping[str, Mapping[str, int]]) -> CorroborationInputs:
    """Aggregates the window's events into the numbers check_corroboration needs.

    Out-of-portfolio (oop) access = an allowed read of a policyholder that is not in the actor's portfolio.
    Export actions are counted apart, whatever their outcome."""
    oop: list[AccessEvent] = []
    for ev in events:
        if ev.outcome == "allowed" and is_policyholder_access(ev) and (ev.resource_id or "") not in portfolio:
            oop.append(ev)
    export_count = sum(1 for ev in events if ev.action == "export")

    policyholders = sorted({ev.resource_id for ev in oop if ev.resource_id})
    owner_counts: dict[str, int] = {}
    unowned = 0
    for ph in policyholders:
        owners = [o for o in owners_of.get(ph, []) if o != actor_id]
        if not owners:
            unowned += 1
        for owner in owners:
            owner_counts[owner] = owner_counts.get(owner, 0) + 1

    per_day: dict[str, int] = {}
    for ev in oop:
        key = ev.ts.date().isoformat()
        per_day[key] = per_day.get(key, 0) + ev.records

    return CorroborationInputs(
        actor_id=actor_id, actor_type=actor_type,
        first_oop_ts=min((e.ts for e in oop), default=None), last_oop_ts=max((e.ts for e in oop), default=None),
        oop_policyholders=len(policyholders), owner_counts=owner_counts, unowned_count=unowned,
        oop_daily_max_records=max(per_day.values(), default=0), export_count=export_count,
        records=list(records), profiles=dict(profiles),
        owner_daily_totals={k: dict(v) for k, v in owner_daily_totals.items()},
    )


# ---- the check ------------------------------------------------------------------------------------------------------

def _author(rec: ContextRecord, *, prefer_payload: bool = False) -> str | None:
    """The author is the created_by column only. The payload is untrusted: a forged "author_id" must not count.
    (`prefer_payload` is kept for call compatibility and ignored.)"""
    return rec.created_by or None


def _span_inside(rec: ContextRecord, first: datetime, last: datetime) -> bool:
    """valid_from / valid_to (columns, valid_to exclusive) are optional; when set, the access span must lie inside."""
    if rec.valid_from is not None and first < rec.valid_from:
        return False
    if rec.valid_to is not None and last >= rec.valid_to:
        return False
    return True


def _record_independent(rec: ContextRecord, author: str | None, x: str, y: str, first: datetime) -> list[str]:
    """Checks every authorising record must pass: created before the first access, written by someone else."""
    codes: list[str] = []
    if rec.created_at is None or rec.created_at >= first:
        codes.append("record_created_after_first_access")
    if author is None:
        codes.append("record_author_unknown")
    elif author in (x, y):
        codes.append("record_authored_by_actor_or_owner")
    return codes


def _path_a(inp: CorroborationInputs, y: str, first: datetime, last: datetime) -> tuple[bool, list[int], list[str], bool]:
    """A transfer, servicing assignment or approval names X for owner Y. Returns (ok, ids, codes, had_candidate)."""
    x = inp.actor_id
    codes: list[str] = []
    candidates = [r for r in inp.records if r.type in AUTHORISING_TYPES and r.named_agent == x and r.subject_agent == y]
    for rec in candidates:
        author = _author(rec, prefer_payload=False)
        rec_codes = _record_independent(rec, author, x, y, first)
        if not _span_inside(rec, first, last):
            rec_codes.append("record_scope_too_narrow")
        # The scope list is kept as a count once the payload is sanitised (policyholder_count); either form is read.
        listed = rec.payload.get("policyholder_ids", rec.payload.get("policyholders"))
        covered = len(listed) if isinstance(listed, list) else rec.payload.get("policyholder_count")
        if isinstance(covered, int) and not isinstance(covered, bool) and covered < inp.owner_counts.get(y, 0):
            rec_codes.append("record_scope_too_narrow")
        if not rec_codes:
            return True, [rec.id], [], True
        codes.extend(rec_codes)
    return False, [], codes, bool(candidates)


def _path_b(inp: CorroborationInputs, y: str, first: datetime, last: datetime) -> tuple[bool, list[int], list[str], bool]:
    """Y has approved leave covering the whole access AND Y's line manager wrote a ticket naming X (body never read)."""
    x = inp.actor_id
    codes: list[str] = []
    leave_ids: list[int] = []
    leave_seen = False
    for rec in inp.records:
        if rec.type != "leave" or rec.subject_agent != y:
            continue
        leave_seen = True
        # A leave row is the HR system of record: approved unless it says otherwise, and it must be entered by
        # someone other than X or Y. Its period is the valid_from / valid_to columns.
        status = str(rec.payload.get("status") or "approved").strip().lower()
        independent = rec.created_by not in (None, "", x, y)
        if (status == "approved" and independent and rec.valid_from is not None and rec.valid_to is not None
                and rec.valid_from <= first and last < rec.valid_to):
            leave_ids.append(rec.id)
    profile = inp.profiles.get(y)
    manager = profile.manager_id if profile else None
    tickets = [r for r in inp.records if r.type == "ticket" and r.subject_agent == y and r.named_agent == x]
    ticket_ids: list[int] = []
    ticket_codes: list[str] = []
    for rec in tickets:
        author = _author(rec, prefer_payload=True)
        rec_codes = _record_independent(rec, author, x, y, first)
        if manager is None or author != manager:
            rec_codes.append("ticket_not_by_line_manager")
        at_creation = rec.payload.get("manager_id_at_creation")
        if at_creation not in (None, "") and str(at_creation) != author:
            rec_codes.append("ticket_not_by_line_manager")
        if not rec_codes:
            ticket_ids.append(rec.id)
        ticket_codes.extend(rec_codes)

    if profile is None:
        codes.append("owner_profile_missing")
    if not leave_ids:
        codes.append("leave_not_approved_or_not_covering")
    if tickets and not ticket_ids:
        codes.extend(ticket_codes)
    elif not tickets and leave_ids:
        codes.append("no_authorising_record")
    ok = bool(leave_ids and ticket_ids and profile is not None)
    return ok, (leave_ids[:1] + ticket_ids[:1]) if ok else [], ([] if ok else codes), bool(tickets or leave_seen)


def check_corroboration(inp: CorroborationInputs) -> Corroboration:
    failed: list[str] = []
    support: list[int] = []

    def fail(code: str) -> None:
        if code not in failed:
            failed.append(code)

    if inp.actor_type != "agent":
        fail("not_agent_actor")
    first, last = inp.first_oop_ts, inp.last_oop_ts
    if first is None or last is None or inp.oop_policyholders == 0:
        fail("no_out_of_portfolio_access")
    if inp.unowned_count > 0:
        fail("unowned_policyholder")
    owners = sorted(inp.owner_counts)
    if len(owners) > MAX_OWNERS:
        fail("too_many_owners")
    if inp.export_count > 0:
        fail("export_in_window")

    if first is not None and last is not None and owners and len(owners) <= MAX_OWNERS and inp.actor_type == "agent":
        for y in owners:
            a_ok, a_ids, a_codes, a_seen = _path_a(inp, y, first, last)
            if a_ok:
                support.extend(a_ids)
                continue
            b_ok, b_ids, b_codes, b_seen = _path_b(inp, y, first, last)
            if b_ok:
                support.extend(b_ids)
                continue
            if not a_seen and not b_seen:
                fail("no_authorising_record")
                continue
            for code in [*(a_codes if a_seen else []), *(b_codes if b_seen else [])]:
                fail(code)

        baseline = 0.0
        history_ok = True
        for y in owners:
            totals = inp.owner_daily_totals.get(y) or {}
            if len(totals) < MIN_BASELINE_DAYS:
                history_ok = False
                continue
            baseline += percentile(list(totals.values()), 0.95) or 0.0
        if not history_ok:
            fail("owner_baseline_missing")
        elif inp.oop_daily_max_records > baseline + 1e-9:
            fail("volume_exceeds_owner_p95")

    if failed:
        return Corroboration(False, failed, [REASON_TEXT.get(c, c) for c in failed], [])
    ids = sorted(set(support))
    reasons = [f"Access to the policyholders of {', '.join(owners)} is covered by record(s) {ids} created before the first "
               "access by someone other than the agent or the owner; volume is within the owner's own 95th percentile "
               "and nothing was exported."]
    return Corroboration(True, [], reasons, ids)


def unavailable_corroboration() -> Corroboration:
    """Used when the context could not be loaded: never ok."""
    return Corroboration(False, ["context_unavailable"], [REASON_TEXT["context_unavailable"]], [])


# ---- guards on the model's answer -----------------------------------------------------------------------------------

def _int_ids(values: Any) -> list[int]:
    if not isinstance(values, (list, tuple)):
        return []
    return [v for v in values if isinstance(v, int) and not isinstance(v, bool)]


def apply_justify_guards(llm_out: Mapping[str, Any] | None, corroboration: Corroboration,
                         fetched_record_ids: Collection[int]) -> Justification:
    """The final verdict is 'justified' only if the model said so AND the code check passed AND the model's cited ids are
    non-empty, all exist in the fetched records, and at least one is a record the check itself relied on.
    Any other 'justified' becomes 'inconclusive' with the gate reasons. The model can never raise a verdict."""
    if llm_out is None:
        return Justification(verdict="inconclusive", llm_verdict=None, gate_reasons=["llm_unavailable"])

    raw_verdict = llm_out.get("verdict")
    llm_verdict = raw_verdict if raw_verdict in VERDICTS else None
    raw_ids = llm_out.get("supporting_record_ids")
    raw_list = list(raw_ids) if isinstance(raw_ids, (list, tuple)) else []
    ints = _int_ids(raw_list)
    fetched = set(fetched_record_ids)
    valid = [i for i in dict.fromkeys(ints) if i in fetched]
    dropped = len(raw_list) - len(valid)

    reasoning = llm_out.get("reasoning")
    missing = llm_out.get("missing_evidence")
    base = dict(
        llm_verdict=llm_verdict, supporting_record_ids=valid, dropped_ids=dropped,
        reasoning=reasoning[:1000] if isinstance(reasoning, str) else "",
        missing_evidence=[m[:200] for m in missing[:8] if isinstance(m, str)] if isinstance(missing, list) else [],
    )

    if llm_verdict is None:
        return Justification(verdict="inconclusive", gate_reasons=["llm_verdict_invalid"], **base)
    if llm_verdict != "justified":
        return Justification(verdict=llm_verdict, gate_reasons=[], **base)

    gates: list[str] = []
    if not corroboration.ok:
        gates.append("corroboration_failed:" + ",".join(corroboration.failed_checks))
    if not ints:
        gates.append("no_supporting_ids")
    if len(ints) != len(raw_list) or any(i not in fetched for i in ints):
        gates.append("cited_unknown_record")
    if ints and not set(ints) & set(corroboration.supporting_record_ids):
        gates.append("cited_ids_not_in_corroboration")
    if gates:
        return Justification(verdict="inconclusive", gate_reasons=gates, **base)
    return Justification(verdict="justified", gate_reasons=[], **base)
