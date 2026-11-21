"""Risk function (T4): the plan's worked values, bands, the partner multiplier, the cap and the I1 floor."""

import pytest

from app.services import risk

# (case, signals, tier, n_records, actor_type, expected risk, expected band); tolerance +/-0.5.
WORKED = [
    ("S1 bad night", {"A1": 0.9, "A2": 0.7, "A3": 0.8, "A4": 0.4}, "T1", 1840, "agent", 88.7, "critical"),
    ("S1b cover", {"A1": 0.9, "A2": 0.7}, "T2", 130, "agent", 54.2, "medium"),
    ("S1d forged ticket on real leave", {"A1": 0.9, "A2": 0.7}, "T2", 150, "agent", 54.7, "medium"),
    ("manager reviewing own team", {"A2": 0.7}, "T2", 300, "agent", 41.0, "medium"),
    ("S2 TPA key", {"P1": 0.9, "P2": 0.8, "P3": 0.6}, "T1", 420, "partner_key", 94.5, "critical"),
    ("S5 terminated agent", {"I1": 0.95}, "T2", 40, "agent", 60.0, "high"),
]


@pytest.mark.parametrize("case,signals,tier,n,actor_type,expected,expected_band", WORKED, ids=[w[0] for w in WORKED])
def test_worked_values(case, signals, tier, n, actor_type, expected, expected_band):
    value, name = risk.score(signals, tier, n, actor_type)
    assert value == pytest.approx(expected, abs=0.5)
    assert name == expected_band


def test_s5_formula_value_before_the_floor():
    # 49.5 by the formula; the I1 floor lifts it to 60.
    raw = 100 * risk.likelihood([0.95]) * (0.4 + 0.6 * risk.impact("T2", 40))
    assert raw == pytest.approx(49.5, abs=0.5)
    assert risk.risk_score({"I1": 0.95}, "T2", 40, "agent") == 60.0


def test_floor_applies_only_when_i1_fired():
    assert risk.risk_score({"A4": 0.4}, "T3", 1, "agent") < 60
    assert risk.risk_score({"A4": 0.4, "I1": 0.95}, "T3", 1, "agent") >= 60


@pytest.mark.parametrize("value,expected", [
    (100.0, "critical"), (80.0, "critical"), (79.9, "high"), (60.0, "high"), (59.9, "medium"),
    (40.0, "medium"), (39.9, "low"), (0.0, "low"),
])
def test_band_boundaries(value, expected):
    assert risk.band(value) == expected


def test_no_signals_is_zero_and_low():
    assert risk.score({}, "T1", 5000, "agent") == (0.0, "low")


def test_partner_multiplier_and_cap():
    agent = risk.risk_score({"P1": 0.9}, "T1", 420, "agent")
    partner = risk.risk_score({"P1": 0.9}, "T1", 420, "partner_key")
    assert partner == pytest.approx(agent * 1.2, abs=0.1)
    assert risk.risk_score({"P1": 1.0, "P2": 1.0}, "T1", 100_000, "partner_key") == 100.0


def test_impact_weights_and_saturation():
    assert risk.impact("T1", 9_999) == pytest.approx(1.0)
    assert risk.impact("T1", 10_000_000) == 1.0
    assert risk.impact("T3", 9_999) == pytest.approx(0.2)
    assert risk.impact(None, 500) == 0.0
    assert risk.impact("T2", 0) == 0.0


def test_confidence_out_of_range_is_refused():
    with pytest.raises(ValueError):
        risk.likelihood([1.2])
