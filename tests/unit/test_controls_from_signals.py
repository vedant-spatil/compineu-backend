"""Controls an incident broke are decided in code from the signals, never by the model."""
from app.orchestration.assembly import controls_from_signals


def test_s1_breaks_portfolio_and_export_only() -> None:
    assert controls_from_signals(["A1", "A2", "A3", "A4"]) == ["C-PORTFOLIO", "C-EXPORT"]


def test_long_rule_names_and_partner_and_inactive() -> None:
    assert controls_from_signals(["I1_inactive_identity", "A2"]) == ["C-INACTIVE"]
    assert controls_from_signals(["P1", "P2", "P3"]) == ["C-PORTFOLIO"]


def test_auto_resolved_justified_cover_breaks_nothing() -> None:
    assert controls_from_signals(["A1", "A2"], {"action": "auto_resolve"}) == []


def test_policyguard_safeguards_are_never_reported_broken() -> None:
    every = controls_from_signals(["A1", "A2", "A3", "A4", "I1", "P1", "P2", "P3"])
    assert not {"C-AUDIT", "C-HUMAN", "C-PII", "C-AGENTS", "C-CERTIN", "C-DPDP72"} & set(every)
