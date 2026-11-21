"""Dashboard incident figures (T11): open incidents by band, CERT-In clocks running, records at risk. Pure, no database."""

from decimal import Decimal

from app.services import dashboard

CLOCKS = {"detected_at": "2026-11-20T18:10:00", "cert_in_due": "2026-11-21T00:10:00", "dpdp_due": "2026-11-23T18:10:00"}


def test_empty_is_all_zeros_with_every_band():
    assert dashboard.incident_figures([]) == {
        "open_incidents_by_band": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "cert_in_clocks_running": 0,
        "records_at_risk": 0,
    }


def test_one_case_per_band_from_the_cases_own_risk():
    rows = [(0.887, {}, 1840), (0.70, {}, 40), (0.542, {}, 130), (0.20, {}, 3)]
    assert dashboard.incident_figures(rows)["open_incidents_by_band"] == {"critical": 1, "high": 1, "medium": 1,
                                                                          "low": 1}


def test_band_uses_the_rounded_risk():
    # 79.96 rounds to 80.0, which is critical, as on the case page.
    assert dashboard.incident_figures([(0.7996, {}, 1)])["open_incidents_by_band"]["critical"] == 1


def test_clocks_count_only_cases_that_have_them():
    rows = [(0.887, {"clocks": CLOCKS, "attempt": 2}, 1), (0.70, {"attempt": 1}, 1), (0.60, {}, 1)]
    assert dashboard.incident_figures(rows)["cert_in_clocks_running"] == 1


def test_a_none_state_and_none_risk_are_safe():
    out = dashboard.incident_figures([(None, None, None)])
    assert out == {"open_incidents_by_band": {"critical": 0, "high": 0, "medium": 0, "low": 1},
                   "cert_in_clocks_running": 0, "records_at_risk": 0}


def test_records_at_risk_sums_the_alert_amounts_as_an_int():
    out = dashboard.incident_figures([(0.887, {}, Decimal("1840.00")), (0.542, {}, 130), (0.60, {}, None)])
    assert out["records_at_risk"] == 1970 and isinstance(out["records_at_risk"], int)


def test_active_statuses_match_the_case_service():
    from app.services.cases import ACTIVE_STATUSES

    assert dashboard.ACTIVE_STATUSES == ACTIVE_STATUSES
