"""The validator and the stored-report contract: the committed sample must satisfy it, and breaking it must be noticed."""

import copy
import json
from pathlib import Path

from app.evaluation.golden_set import sample_report
from app.evaluation.report_contract import STORED_REPORT_SCHEMA, validate
from app.orchestration.prompts import JUSTIFY_SCHEMA

SAMPLE = Path(__file__).resolve().parents[2] / "docs" / "samples" / "incident_report.sample.json"


def test_the_committed_sample_matches_the_contract():
    assert validate(json.loads(SAMPLE.read_text(encoding="utf-8")), STORED_REPORT_SCHEMA) == []


def test_a_report_assembled_by_code_matches_the_contract():
    assert validate(sample_report(), STORED_REPORT_SCHEMA) == []


def test_breaking_the_contract_is_reported():
    bad = copy.deepcopy(sample_report())
    bad["risk_score"] = "89"
    bad["cited_event_ids"] = [1, "2", True]
    bad["controls_failed"] = ["C-PORTFOLIO", "FAKE-1"]
    bad["justification"]["llm_verdict"] = 5
    del bad["actor"]
    bad["extra"] = 1
    errors = validate(bad, STORED_REPORT_SCHEMA)
    for fragment in ("$.risk_score", "$.cited_event_ids[1]", "$.cited_event_ids[2]", "$.controls_failed[1]",
                     "$.justification.llm_verdict", "$.actor: missing", "$.extra: unexpected key"):
        assert any(fragment in e for e in errors), (fragment, errors)


def test_a_null_llm_verdict_is_allowed_and_the_prompt_schemas_work_with_the_validator():
    ok = copy.deepcopy(sample_report())
    ok["justification"]["llm_verdict"] = None
    assert validate(ok, STORED_REPORT_SCHEMA) == []
    answer = {"verdict": "justified", "supporting_record_ids": [1, 2], "missing_evidence": [], "reasoning": "x"}
    assert validate(answer, JUSTIFY_SCHEMA) == []
    assert validate({**answer, "verdict": "maybe", "extra": 1, "supporting_record_ids": ["1"]}, JUSTIFY_SCHEMA)
