"""GET /api/quality (admin, T10): detection quality on the replayed scenarios, for the quality page and the slides.

Ground truth is read here and only here: an incident (a PolicyGuard alert) is an attack when any event it cites
(alert.raw_json["txn_ids"]) has labels.is_attack true, and each labelled scenario run is identified by labels.scenario.
An alert whose cited events no longer exist (a reset deletes replayed events) belongs to an earlier rehearsal and is
not counted, so the page shows the runs since the last reset.

- AI off: every alert with Risk >= 40 is an incident.
- AI on: the same, minus cases the AI auto-resolved.
- Precision = true positives / incidents. Recall = attack scenario runs caught by at least one incident / attack runs.
- Time to detect: alert.ts minus the run's first attack event ts, in simulated minutes (both are on the replay's
  clock), median over the caught attack runs.
- golden_set: Bhavya's offline and live golden-set results, read from the JSON files app.evaluation.golden_set writes.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import db_session, require_role
from app.db import models

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["quality"], dependencies=[Depends(require_role("admin"))])

INCIDENT_RISK = 40.0
AUTO_RESOLVED = "auto_resolved"


# ------------------------------------------------------------------ the numbers (pure)


def _rates(incidents: list[dict[str, Any]], attack_runs: set[tuple[str, str]]) -> dict[str, Any]:
    tp = [i for i in incidents if i["is_attack"]]
    caught = {(i["scenario"], i["actor"]) for i in tp} & attack_runs
    return {
        "incidents": len(incidents),
        "true_positives": len(tp),
        "false_positives": len(incidents) - len(tp),
        "precision": round(len(tp) / len(incidents), 3) if incidents else 0.0,
        "recall": round(len(caught) / len(attack_runs), 3) if attack_runs else 0.0,
    }


def summarize(alerts: list[dict[str, Any]], runs: dict[tuple[str, str], dict[str, Any]],
              manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """`alerts`: one dict per counted PolicyGuard alert: id, actor, ts, risk (0-100), rules, status (its case's, or
    None), scenario (the label most of its cited events carry, or None), is_attack.
    `runs`: (scenario, actor) -> {"is_attack", "first_attack_ts"} for every labelled scenario run in access_events."""
    manifest = manifest or {}
    attack_runs = {key for key, run in runs.items() if run["is_attack"]}
    ai_off = [a for a in alerts if a["risk"] >= INCIDENT_RISK]
    ai_on = [a for a in ai_off if a["status"] != AUTO_RESOLVED]

    minutes = []
    for key in attack_runs:
        hits = [a["ts"] for a in ai_off if a["is_attack"] and (a["scenario"], a["actor"]) == key]
        first = runs[key].get("first_attack_ts")
        if hits and first is not None:
            minutes.append(max(0.0, (min(hits) - first).total_seconds() / 60))

    scenarios = []
    for (scenario, actor), run in sorted(runs.items()):
        mine = [a for a in alerts if (a["scenario"], a["actor"]) == (scenario, actor)]
        latest = max(mine, key=lambda a: a["id"]) if mine else None
        expected = (manifest.get(scenario) or {}).get("expected_route") or ("incident" if run["is_attack"] else
                                                                            "no_incident")
        status = "not_detected"
        if latest is not None:
            status = latest["status"] or ("logged" if latest["risk"] < INCIDENT_RISK else "no_case")
        scenarios.append({"scenario": scenario, "actor": actor, "expected": expected,
                          "risk": latest["risk"] if latest else 0.0, "status": status})

    signals_total = sum(len(a["rules"]) for a in ai_off)
    return {
        "scenarios": scenarios,
        "ai_off": _rates(ai_off, attack_runs),
        "ai_on": _rates(ai_on, attack_runs),
        "time_to_detect_sim_minutes_median": round(median(minutes), 1) if minutes else 0.0,
        "signals_total": signals_total,
        "signals_per_incident": round(signals_total / len(ai_off), 2) if ai_off else 0.0,
    }


# ------------------------------------------------------------------ the database side


def _load(db: Session) -> tuple[list[dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    table = models.AccessEvent.__table__
    rows = db.execute(select(models.Alert).where(models.Alert.source_label == "policyguard")).scalars().all()
    cited_ids = {int(i) for a in rows for i in (a.raw_json or {}).get("txn_ids", [])}
    labels: dict[int, dict[str, Any]] = {}
    if cited_ids:
        for event_id, lab in db.execute(select(table.c.id, table.c.labels).where(table.c.id.in_(cited_ids))):
            labels[event_id] = lab if isinstance(lab, dict) else {}
    status: dict[int, str] = {}
    for alert_id, case_status in db.execute(select(models.Case.alert_id, models.Case.status).order_by(models.Case.id)):
        status[alert_id] = case_status  # the latest case wins

    alerts = []
    for a in rows:
        cited = [labels[int(i)] for i in (a.raw_json or {}).get("txn_ids", []) if int(i) in labels]
        if not cited:
            continue  # an earlier rehearsal: its events were reset
        names = Counter(lab.get("scenario") for lab in cited if lab.get("scenario"))
        alerts.append({"id": a.id, "actor": a.account_id, "ts": a.ts, "risk": round(float(a.risk_score) * 100, 1),
                       "rules": list(a.rules or []), "status": status.get(a.id),
                       "scenario": names.most_common(1)[0][0] if names else None,
                       "is_attack": any(bool(lab.get("is_attack")) for lab in cited)})

    runs: dict[tuple[str, str], dict[str, Any]] = {}
    for lab, actor, ts in db.execute(select(table.c.labels, table.c.actor_id, table.c.ts)
                                     .where(table.c.labels["scenario"].as_string().is_not(None))):
        run = runs.setdefault((lab["scenario"], actor), {"is_attack": False, "first_attack_ts": None})
        if lab.get("is_attack"):
            run["is_attack"] = True
            if run["first_attack_ts"] is None or ts < run["first_attack_ts"]:
                run["first_attack_ts"] = ts
    return alerts, runs


def _manifest() -> dict[str, Any]:
    """Expected routes per scenario, from the replay's world (Sumit's generator). Empty if unavailable."""
    try:
        from app.portal.replay import _world

        return _world()["manifest"]
    except Exception:  # the page still works without expectations
        log.warning("quality: scenario manifest unavailable", exc_info=True)
        return {}


def _golden_paths() -> tuple[Path, Path]:
    try:
        from app.evaluation.golden_set import DEFAULT_OUT, LIVE_OUT

        return DEFAULT_OUT, LIVE_OUT
    except Exception:  # noqa: BLE001 - fall back to the same paths as Bhavya's module
        root = Path(__file__).resolve().parents[3] / "docs" / "eval"
        return root / "golden_set_results.json", root / "golden_set_live_results.json"


def _golden_file(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        return {"path": str(path), "error": f"unreadable: {type(exc).__name__}"}
    failed = data.get("assertions_failed")
    return {"path": str(path), "scenarios": len(data.get("scenarios") or []), "metrics": data.get("metrics"),
            "assertions_failed": len(failed) if isinstance(failed, list) else failed}


def golden_set() -> dict[str, Any]:
    offline, live = _golden_paths()
    return {"offline": _golden_file(offline), "live": _golden_file(live)}


@router.get("/quality")
def quality(db: Session = Depends(db_session)) -> dict[str, Any]:
    alerts, runs = _load(db)
    return {**summarize(alerts, runs, _manifest()), "golden_set": golden_set()}
