"""Mock portal and partner API rules, against the committed fixture (no database)."""
from pathlib import Path

import pytest

from app.portal import service
from app.portal.service import Ctx, PortalError
from app.portal.store import MemoryStore

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "pg_small"


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore.from_dir(FIXTURE)


def _someone_elses_customer(store: MemoryStore, agent: str) -> str:
    return next(p for p, ph in store.policyholders.items() if ph["agent_id"] != agent and ph["product"] == "health")


def test_out_of_portfolio_view_is_allowed_and_recorded(store) -> None:
    ph = _someone_elses_customer(store, "AG-1147")
    out = service.view(store, Ctx("AG-1147", ip="100.72.18.24", device="dv-9f2c", city="Lucknow"), ph)
    assert out["policyholder"]["policyholder_id"] == ph
    e = store.events[-1]
    assert (e["action"], e["resource_id"], e["policyholder_id"], e["outcome"], e["tier"], e["records"]) == \
        ("view", ph, ph, "allowed", "T1", 1)
    assert e["device"] == "dv-9f2c" and "T" in e["ts"] and "+" not in e["ts"] and not e["ts"].endswith("Z")


def test_suspended_agent_gets_403_and_the_attempt_is_recorded(store) -> None:
    store.agents["AG-1147"]["hr_status"] = "suspended"   # what PB1 does
    with pytest.raises(PortalError) as err:
        service.view(store, Ctx("AG-1147"), _someone_elses_customer(store, "AG-1147"))
    assert err.value.status == 403
    assert store.events[-1]["outcome"] == "denied" and store.events[-1]["records"] == 0


def test_disabled_credential_gets_403(store) -> None:
    store.agents["AG-1033"]["credential_enabled"] = False
    with pytest.raises(PortalError) as err:
        service.search(store, Ctx("AG-1033"), "city=Pune")
    assert err.value.status == 403


def test_terminated_agent_with_live_credential_gets_through(store) -> None:
    """Scenario S5: HR terminated AG-0577 but IT never disabled the credential. The portal must not hide that gap."""
    assert store.agents["AG-0577"]["hr_status"] == "terminated"
    ph = next(p for p, v in store.policyholders.items() if v["agent_id"] == "AG-0577")
    service.view(store, Ctx("AG-0577"), ph)
    assert store.events[-1]["outcome"] == "allowed"


def test_unknown_policyholder_is_404_and_recorded(store) -> None:
    with pytest.raises(PortalError) as err:
        service.view(store, Ctx("AG-1147"), "PH-99999999")
    assert err.value.status == 404 and store.events[-1]["outcome"] == "not_found"


def test_search_lists_names_without_counting_records(store) -> None:
    out = service.search(store, Ctx("AG-1147"), "city=Pune product=health")
    assert 0 < len(out["results"]) <= service.SEARCH_LIMIT
    e = store.events[-1]
    assert e["records"] == 0 and e["tier"] == "T3" and e["detail"]["results_listed"] == len(out["results"])


def test_export_with_sensitive_fields_is_t1_with_row_count(store) -> None:
    out = service.export(store, Ctx("AG-1147"), "city=Nagpur", 1200, ["policyholder_id", "diagnosis"])
    e = store.events[-1]
    assert out["rows"] == 1200 and (e["action"], e["resource_type"], e["tier"], e["records"]) == \
        ("export", "export_file", "T1", 1200)
    service.export(store, Ctx("AG-1147"), "city=Pune product=motor", 50, ["policyholder_id", "name"])
    assert store.events[-1]["tier"] == "T2"


def test_partner_gets_any_existing_claim_but_404_for_missing_and_403_when_disabled(store) -> None:
    claim_id, claim = next(iter(store.claims.items()))
    other = next(k for k in store.partner_keys if k != claim["tpa_key"])
    assert service.partner_claim(store, Ctx(other), claim_id)["claim"]["claim_id"] == claim_id  # unassigned: allowed
    with pytest.raises(PortalError) as err:
        service.partner_claim(store, Ctx(other), "CL-1")
    assert err.value.status == 404
    store.partner_keys[other]["enabled"] = False   # what PB2 does
    with pytest.raises(PortalError) as err:
        service.partner_claim(store, Ctx(other), claim_id)
    assert err.value.status == 403 and store.events[-1]["outcome"] == "denied"


def test_replay_context_is_kept(store) -> None:
    ph = _someone_elses_customer(store, "AG-1147")
    service.view(store, Ctx("AG-1147", ts="2026-11-20T18:10:00", event_id="ev-s1-00004",
                            labels={"scenario": "S1", "is_attack": True}), ph)
    e = store.events[-1]
    assert (e["ts"], e["event_id"], e["labels"]["scenario"]) == ("2026-11-20T18:10:00", "ev-s1-00004", "S1")
