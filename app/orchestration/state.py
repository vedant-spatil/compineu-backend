import operator
from typing import Annotated, Any, TypedDict


class CaseState(TypedDict, total=False):
    """Graph state. Everything here is JSON-safe and name-free: LangGraph checkpoints store it in plain.
    Names live only in the encrypted identity_map on Case.state."""

    case_id: int
    alert_id: int
    account_id: str  # the actor: an agent id (AG-1147) or a partner key id
    alert_ts: str  # ISO 8601
    alert_rules: list[str]
    risk_score: float  # 0..1 (alerts.risk_score)
    txn_ids: list[int]  # integer access_events ids from alert.raw_json['txn_ids'] (name kept for compatibility)
    status: str  # open | awaiting_review | approved | closed | failed | closed_low_risk | auto_resolved
    context: dict[str, Any]  # load_context: actor profile, window, corroboration inputs, data gaps
    clocks: dict[str, str]  # load_context: detected_at, cert_in_due, dpdp_due and their labels
    evidence: dict[str, Any]  # gather_evidence: timeline, portfolio overlap, tier counts, exports
    justification: dict[str, Any]  # justify: final verdict, gate reasons, corroboration result
    classification: dict[str, Any]  # classify: scenario, attack techniques, cited event ids
    route: dict[str, Any]  # route_case: action, band, blockers
    incident_report: dict[str, Any] | None  # report_writer: the REPORT JSON
    sar_draft: dict[str, Any] | None  # same object as incident_report (backward compatibility)
    failures: Annotated[list[str], operator.add]  # parallel branches append
    decision: dict[str, Any] | None
