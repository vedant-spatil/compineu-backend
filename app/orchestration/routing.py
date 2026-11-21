"""Routing after the parallel branches (plan section 5). Pure: no database, no model, no clock.

RULES DETECT, AI EXPLAINS, CODE DECIDES WHETHER PROOF EXISTS. A medium alert is closed automatically only when every gate
below holds. The model's verdict is one input; it can never open the gate by itself.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

INCIDENT_THRESHOLD = 0.60
_EPS = 1e-9

# I1: identity that HR or IAM says should be inactive. Never closed without a human.
HARD_SIGNALS = frozenset({"I1"})
# Partner signals and the bulk export signal are never auto-resolved either.
NEVER_AUTO_RESOLVE = HARD_SIGNALS | frozenset({"P1", "P2", "P3", "A3"})
# A failure from one of these nodes means the proof is missing, so the alert is promoted to a human.
BLOCKING_FAILURE_NODES = frozenset({"load_context", "evidence", "justification"})

_SIGNAL_RE = re.compile(r"^[A-Za-z]\d+")


def signal_id(rule: Any) -> str:
    """'I1_inactive_identity' -> 'I1', 'I1' -> 'I1', 'a1:out' -> 'A1'. Falls back to the text before the first '_'."""
    text = str(rule).strip()
    match = _SIGNAL_RE.match(text)
    return (match.group(0) if match else text.split("_")[0]).upper()


def failure_node(failure: str) -> str:
    """'justification: llm failed' -> 'justification'."""
    return str(failure).split(":", 1)[0].strip()


@dataclass(frozen=True)
class RouteDecision:
    action: str  # "auto_resolve" | "investigate"
    band: str  # "incident" | "medium"
    reasons: tuple[str, ...]
    blockers: tuple[str, ...]  # why a medium alert was promoted; empty for incidents and auto-resolves

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "band": self.band, "reasons": list(self.reasons),
                "blockers": list(self.blockers)}


def route_decision(score: float, alert_rules: Sequence[Any], justification: Mapping[str, Any] | None,
                   failures: Sequence[str]) -> RouteDecision:
    """score is the alert's 0..1 risk (alerts.risk_score). Alerts under the triage floor never reach this function."""
    if float(score) >= INCIDENT_THRESHOLD - _EPS:
        return RouteDecision("investigate", "incident", (f"score {float(score):.2f} is at or above {INCIDENT_THRESHOLD:.2f}",), ())

    blockers: list[str] = []
    signals = sorted({signal_id(r) for r in alert_rules or []})
    for sig in signals:
        if sig in HARD_SIGNALS:
            blockers.append(f"hard_signal:{sig}")
        elif sig in NEVER_AUTO_RESOLVE:
            blockers.append(f"never_auto_signal:{sig}")
    if not justification:
        blockers.append("justification_missing")
    else:
        verdict = justification.get("verdict")
        if verdict != "justified":
            blockers.append(f"verdict_not_justified:{verdict}")
        corroboration = justification.get("corroboration") or {}
        if corroboration.get("ok") is not True:
            blockers.append("corroboration_not_ok")
    for failure in failures or []:
        node = failure_node(failure)
        if node in BLOCKING_FAILURE_NODES:
            code = f"failure:{node}"
            if code not in blockers:
                blockers.append(code)

    if blockers:
        return RouteDecision("investigate", "medium", ("medium alert promoted to a human review",), tuple(blockers))
    return RouteDecision("auto_resolve", "medium",
                         ("medium alert, verdict justified, corroborated by records in code, no hard signal",), ())
