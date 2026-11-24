"""GET /api/quality (T10): the metrics over hand-made alerts and scenario runs, the golden-set files, the route."""

import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from app.api.routers import quality as q
from app.db import models

T0 = datetime(2026, 11, 20, 11, 0)


def alert(i, scenario, actor, risk, rules, status, is_attack, minutes_after_start):
    return {"id": i, "actor": actor, "ts": T0 + timedelta(minutes=minutes_after_start), "risk": risk, "rules": rules,
            "status": status, "scenario": scenario, "is_attack": is_attack}


ALERTS = [
    alert(1, "S1", "AG-1147", 88.7, ["A1", "A2", "A3", "A4"], "awaiting_review", True, 5),
    alert(2, "S1b", "AG-1033", 54.2, ["A1", "A2"], "auto_resolved", False, 9),   # benign cover, AI resolves it
    alert(3, "S1c", "AG-1088", 54.2, ["A1", "A2"], "awaiting_review", True, 3),
    alert(4, "D3", "AG-1012", 39.4, ["A2"], None, False, 40),                    # logged, no case
]
RUNS = {
    ("S1", "AG-1147"): {"is_attack": True, "first_attack_ts": T0},
    ("S1b", "AG-1033"): {"is_attack": False, "first_attack_ts": None},
    ("S1c", "AG-1088"): {"is_attack": True, "first_attack_ts": T0},
    ("S5", "AG-0577"): {"is_attack": True, "first_attack_ts": T0},             # missed
    ("D3", "AG-1012"): {"is_attack": False, "first_attack_ts": None},
}
MANIFEST = {"S1": {"expected_route": "incident"}, "S1b": {"expected_route": "auto_resolve"},
            "D3": {"expected_route": "logged"}}


def test_ai_off_counts_every_alert_at_40_or_more():
    out = q.summarize(ALERTS, RUNS, MANIFEST)
    assert out["ai_off"] == {"incidents": 3, "true_positives": 2, "false_positives": 1, "precision": 0.667,
                             "recall": 0.667}


def test_ai_on_drops_what_the_ai_auto_resolved():
    out = q.summarize(ALERTS, RUNS, MANIFEST)
    assert out["ai_on"] == {"incidents": 2, "true_positives": 2, "false_positives": 0, "precision": 1.0,
                            "recall": 0.667}


def test_time_to_detect_and_signals():
    out = q.summarize(ALERTS, RUNS, MANIFEST)
    assert out["time_to_detect_sim_minutes_median"] == 4.0  # S1 after 5 minutes, S1c after 3
    assert out["signals_total"] == 8 and out["signals_per_incident"] == 2.67


def test_one_row_per_scenario_run():
    rows = {r["scenario"]: r for r in q.summarize(ALERTS, RUNS, MANIFEST)["scenarios"]}
    assert rows["S1"] == {"scenario": "S1", "actor": "AG-1147", "expected": "incident", "risk": 88.7,
                          "status": "awaiting_review"}
    assert rows["S1b"]["expected"] == "auto_resolve" and rows["S1b"]["status"] == "auto_resolved"
    assert rows["D3"]["status"] == "logged"
    assert rows["S5"] == {"scenario": "S5", "actor": "AG-0577", "expected": "incident", "risk": 0.0,
                          "status": "not_detected"}  # no manifest entry: expected comes from the label


def test_the_shape_the_frontend_builds_against():
    out = q.summarize(ALERTS, RUNS, MANIFEST)
    assert set(out) == {"scenarios", "ai_off", "ai_on", "time_to_detect_sim_minutes_median", "signals_total",
                        "signals_per_incident"}
    assert set(out["scenarios"][0]) == {"scenario", "actor", "expected", "risk", "status"}


def test_nothing_replayed_is_all_zeros():
    out = q.summarize([], {})
    assert out["ai_off"] == {"incidents": 0, "true_positives": 0, "false_positives": 0, "precision": 0.0,
                             "recall": 0.0}
    assert out["scenarios"] == [] and out["time_to_detect_sim_minutes_median"] == 0.0


def test_golden_set_files(tmp_path):
    good = tmp_path / "golden_set_results.json"
    good.write_text(json.dumps({"scenarios": [{}, {}], "metrics": {"accuracy": 0.92}, "assertions_failed": []}))
    assert q._golden_file(good) == {"path": str(good), "scenarios": 2, "metrics": {"accuracy": 0.92},
                                    "assertions_failed": 0}
    assert q._golden_file(tmp_path / "missing.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert q._golden_file(bad)["error"].startswith("unreadable")


def test_golden_set_paths_match_eval_module():
    from app.evaluation.golden_set import DEFAULT_OUT, LIVE_OUT

    assert q._golden_paths() == (DEFAULT_OUT, LIVE_OUT)


def test_route_adds_the_golden_set(monkeypatch):
    monkeypatch.setattr(q, "_load", lambda db: (ALERTS, RUNS))
    monkeypatch.setattr(q, "_manifest", lambda: MANIFEST)
    monkeypatch.setattr(q, "golden_set", lambda: {"offline": None, "live": None})
    out = q.quality(db=None)
    assert out["golden_set"] == {"offline": None, "live": None} and out["ai_on"]["precision"] == 1.0


def test_route_is_registered_for_admins_only():
    from app.main import app

    assert set(app.openapi()["paths"]["/api/quality"]) == {"get"}  # included routers are nested in FastAPI 0.146
    assert q.router.dependencies  # require_role("admin") on the whole router


def test_scenario_filter_compiles_to_postgres_json_text():
    table = models.AccessEvent.__table__
    stmt = select(table.c.actor_id).where(table.c.labels["scenario"].as_string().is_not(None))
    assert "->>" in str(stmt.compile(dialect=postgresql.dialect()))


@pytest.mark.parametrize("risk,status,expected", [(39.9, None, "logged"), (40.0, None, "no_case")])
def test_status_without_a_case(risk, status, expected):
    rows = q.summarize([alert(9, "D2", "AG-1055", risk, ["A2"], status, False, 1)],
                       {("D2", "AG-1055"): {"is_attack": False, "first_attack_ts": None}})["scenarios"]
    assert rows[0]["status"] == expected
