"""Scenario floor: code derives the label from signals and checks, so a wrong model label (the light model called the S1 bad
night "negligent" and the forged ticket "benign_exception") never reaches the screen as report.scenario."""

import pytest

from app.evaluation import golden_set as gs
from app.orchestration.assembly import apply_scenario_floor, scenario_floor


def _case(sc: gs.Scenario, verdict: str | None = None):
    """The code check's view of a golden-set scenario: (corroboration_ok, failed_checks)."""
    res = gs.run_chain(sc, "stub")
    corro = res["corroboration"]
    return corro.ok, corro.failed_checks, res["justification"].verdict if verdict is None else verdict


def test_s1_export_and_unusual_context_with_a_negligent_label_become_malicious_insider():
    sc = gs.build_s1()
    assert {"A3_bulk_export", "A4_unusual_context"} <= set(sc.rules)
    ok, failed, _ = _case(sc)
    assert ok is False
    label, source, reason = scenario_floor("negligent", sc.rules, corroboration_ok=ok, failed_checks=failed, risk_score=sc.score)
    assert (label, source) == ("malicious_insider", "code_floor")
    assert "signal A3" in reason and "signal A4" in reason and "risk 0.89" in reason


def test_s1c_forged_ticket_with_a_benign_label_becomes_malicious_insider():
    sc = gs.build_s1c()
    ok, failed, _ = _case(sc)
    assert ok is False and "record_authored_by_actor_or_owner" in failed
    assert sc.score < 0.60 and not {"A3", "A4"} & {r[:2] for r in sc.rules}  # only the forged-evidence check applies
    label, source, reason = scenario_floor("benign_exception", sc.rules, corroboration_ok=ok, failed_checks=failed,
                                           risk_score=sc.score)
    assert (label, source) == ("malicious_insider", "code_floor") and "record_authored_by_actor_or_owner" in reason


def test_s1d_forged_ticket_on_a_real_leave_is_also_malicious_insider():
    sc = gs.build_s1d()
    ok, failed, _ = _case(sc)
    assert "ticket_not_by_line_manager" in failed
    assert scenario_floor("negligent", sc.rules, corroboration_ok=ok, failed_checks=failed,
                          risk_score=sc.score)[:2] == ("malicious_insider", "code_floor")


@pytest.mark.parametrize("model_label", ["negligent", "malicious_insider", "benign_exception"])
def test_s1b_corroborated_and_justified_is_benign_exception(model_label):
    sc = gs.build_s1b()
    ok, failed, verdict = _case(sc)
    assert ok is True and verdict == "justified" and failed == []
    label, source, _ = scenario_floor(model_label, sc.rules, corroboration_ok=ok, failed_checks=failed, verdict=verdict,
                                      risk_score=sc.score)
    assert label == "benign_exception"
    assert source == ("model" if model_label == "benign_exception" else "code_floor")


def test_s1b_before_the_verdict_exists_the_model_label_stands():
    sc = gs.build_s1b()
    ok, failed, _ = _case(sc)
    assert scenario_floor("negligent", sc.rules, corroboration_ok=ok, failed_checks=failed, verdict=None,
                          risk_score=sc.score) == ("negligent", "model", "")


@pytest.mark.parametrize("model_label", ["malicious_insider", "benign_exception", "negligent"])
def test_s5_inactive_identity_is_compromised_account(model_label):
    sc = gs.build_s5()
    ok, failed, _ = _case(sc)
    label, source, reason = scenario_floor(model_label, sc.rules, corroboration_ok=ok, failed_checks=failed, risk_score=sc.score)
    assert label == "compromised_account"
    assert (source == "model") == (model_label == "compromised_account")
    assert ("I1" in reason) == (source == "code_floor")


def test_s2_partner_signal_is_compromised_partner():
    sc = gs.build_s2()
    ok, failed, _ = _case(sc)
    assert scenario_floor("malicious_insider", sc.rules, corroboration_ok=ok, failed_checks=failed,
                          risk_score=sc.score)[:2] == ("compromised_partner", "code_floor")
    assert scenario_floor("compromised_partner", ["P3_new_country"], corroboration_ok=False)[:2] == ("compromised_partner", "model")


def test_a_malicious_insider_label_is_never_lowered_or_changed_when_no_floor_applies():
    assert scenario_floor("malicious_insider", ["A1_out_of_portfolio"], corroboration_ok=False,
                          failed_checks=["no_authorising_record"], risk_score=0.5) == ("malicious_insider", "model", "")
    # even when the checks pass but the verdict is not justified
    assert scenario_floor("malicious_insider", ["A1_out_of_portfolio"], corroboration_ok=True, verdict="inconclusive",
                          risk_score=0.5) == ("malicious_insider", "model", "")


def test_a_soft_label_with_no_forgery_no_export_and_a_medium_score_is_kept():
    assert scenario_floor("negligent", ["A1_out_of_portfolio", "A2_volume_spike"], corroboration_ok=False,
                          failed_checks=["volume_exceeds_owner_p95"], risk_score=0.54) == ("negligent", "model", "")
    assert scenario_floor("benign_exception", ["A1_out_of_portfolio"], corroboration_ok=False,
                          failed_checks=["no_authorising_record"], risk_score=0.60)[:2] == ("malicious_insider", "code_floor")


def test_no_code_view_of_the_checks_means_no_floor_except_the_signal_rules():
    assert scenario_floor("negligent", ["A1_out_of_portfolio", "A3_bulk_export"], corroboration_ok=None,
                          risk_score=0.9) == ("negligent", "model", "")
    assert scenario_floor("negligent", ["I1"], corroboration_ok=None)[:2] == ("compromised_account", "code_floor")
    assert scenario_floor(None, ["A1_out_of_portfolio"], corroboration_ok=False, risk_score=0.9) == (None, "model", "")


def test_apply_keeps_the_model_label_and_can_be_repeated_when_the_verdict_arrives():
    cls = {"scenario": "negligent", "attack_techniques": [], "cited_event_ids": [1], "confidence": 0.7, "dropped_ids": 0}
    first = apply_scenario_floor(cls, ["A1_out_of_portfolio"], corroboration_ok=True, failed_checks=[], risk_score=0.54)
    assert (first["scenario"], first["scenario_source"], first["model_scenario"]) == ("negligent", "model", "negligent")
    second = apply_scenario_floor(first, ["A1_out_of_portfolio"], corroboration_ok=True, failed_checks=[], verdict="justified",
                                  risk_score=0.54)
    assert (second["scenario"], second["scenario_source"], second["model_scenario"]) == (
        "benign_exception", "code_floor", "negligent")
    assert second["floor_reason"] and second["confidence"] == 0.7 and second["cited_event_ids"] == [1]
    assert cls["scenario"] == "negligent"  # the input is not changed
