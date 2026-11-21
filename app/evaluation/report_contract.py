"""The stored incident report as the frontend reads it (docs/samples/incident_report.sample.json, src/api/report.ts), written as
a JSON-schema-style dict, plus a small validator for the subset of JSON Schema that this repo's prompts and report use
(type, enum, properties, required, additionalProperties, items). No third-party library.

Used by the live golden set (is the stored report well-formed?) and by the sample-vs-real comparison."""

from typing import Any

from app.orchestration.controls import CONTROL_IDS, PLAYBOOK_IDS
from app.orchestration.prompts import SCENARIOS, VERDICTS

_S = {"type": "string"}
_I = {"type": "integer"}
_STRINGS = {"type": "array", "items": _S}


def _obj(props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


STORED_REPORT_SCHEMA: dict[str, Any] = _obj({
    "title": _S,
    "summary": _S,
    "detected_at": _S,
    "risk_score": _I,
    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
    "scenario": {"type": "string", "enum": [*SCENARIOS, "unclassified"]},
    "attack_techniques": _STRINGS,
    "cited_event_ids": {"type": "array", "items": _I},
    "timeline": {"type": "array", "items": _obj({"event_id": _I, "ts": _S, "what": _S})},
    "impact": _obj({"records": _I, "rows_exported": _I, "policyholders": _I, "outside_portfolio_records": _I,
                    "tiers": _obj({"T1": _I, "T2": _I, "T3": _I})}),
    "justification": _obj({
        "verdict": {"type": "string", "enum": VERDICTS},
        "llm_verdict": {"type": ["string", "null"], "enum": VERDICTS},
        "reasoning": _S,
        "supporting_record_ids": {"type": "array", "items": _I},
        "missing_evidence": _STRINGS,
        "corroboration": _obj({"ok": {"type": "boolean"}, "failed_checks": _STRINGS, "reasons": _STRINGS}),
        "gate_reasons": _STRINGS,
        "closes_incident": {"type": "boolean"},
    }),
    "recommended_playbooks": {"type": "array", "items": {"type": "string", "enum": list(PLAYBOOK_IDS)}},
    "controls_failed": {"type": "array", "items": {"type": "string", "enum": list(CONTROL_IDS)}},
    "cert_in_draft": _obj({k: _S for k in ("summary", "incident_type", "systems_affected", "timeline_summary", "actions_taken")}),
    "dpdp_intimation_draft": _obj({k: _S for k in ("nature", "extent", "timing", "location", "likely_impact")}),
    "open_questions": _STRINGS,
    "actor": _S,
    "clocks": _obj({k: _S for k in ("detected_at", "cert_in_due", "cert_in_label", "dpdp_due", "dpdp_label")}),
    "draft_notice": _S,
})


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    return False


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Every way `value` breaks `schema`, as short messages. An empty list means valid."""
    kind = schema.get("type")
    names = kind if isinstance(kind, list) else [kind] if kind else []
    if names and not any(_is_type(value, n) for n in names):
        return [f"{path}: expected {'/'.join(names)}, got {type(value).__name__}"]
    errors: list[str] = []
    if "enum" in schema and not (value is None and "null" in names) and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not one of {schema['enum']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        errors += [f"{path}.{k}: missing" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            errors += [f"{path}.{k}: unexpected key" for k in value if k not in props]
        for key, sub in props.items():
            if key in value:
                errors += validate(value[key], sub, f"{path}.{key}")
    elif isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors += validate(item, schema["items"], f"{path}[{i}]")
    return errors
