"""Scenario replay and demo reset (plan section 8, combined plan 12.10).

The replay sends each scenario event through the mock portal or partner API functions (never straight into the
table), so the demo exercises the whole path: portal -> access_events -> detection -> case -> workflow.

Timing: the scenario is shifted to start "now" and runs at `speed` (default 60x: one simulated minute per second;
S1's 38 minutes take about 38 seconds). Event timestamps are on the simulated clock (start + offset), and detection
is called with that simulated "now" every `tick_s` seconds of real time and once at the end, so its 60-minute
window sees the whole burst.

Detection is `app.services.detection.process_actor(actor_id, now)`. Until that module exists, the replay
still writes the events and reports `detection: unavailable` in its status.

Reset (between rehearsals): stops replays, marks active cases (open, awaiting_review) `superseded` (the audit trigger
forbids deleting case_events, and that is the point: even the demo reset cannot erase the audit trail), deletes the
replayed and ad-hoc portal events (history stays), and restores every agent's HR status and credential and every
partner key to the seeded values, which undoes PB1 and PB2.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Callable

from app.portal import service
from app.portal.store import PortalStore

log = logging.getLogger(__name__)

DEFAULT_SPEED = 60.0
TICK_S = 3.0
_lock = threading.Lock()
_runs: dict[str, dict[str, Any]] = {}
_stop = threading.Event()


# ---------------------------------------------------------------------------------------------- scenario data
@lru_cache(maxsize=1)
def _world() -> dict[str, Any]:
    """Scenario events and seeded actor states, regenerated in-process (deterministic, ~2 s, same as the load)."""
    from app.ingest import pg_generate as g

    w = g.build_world()
    g.build_scenarios(w, full=True)
    return {
        "scenarios": w.scenarios,
        "manifest": w.manifest,
        "agents": {a: (v["hr_status"], v["credential_enabled"]) for a, v in {**w.agents, **w.managers}.items()},
    }


def scenario_ids() -> list[str]:
    return sorted(_world()["scenarios"])


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------------------------- one event
def send(store: PortalStore, e: dict[str, Any], ts: datetime, run: str) -> str:
    """Send one scenario event through the portal function for its action. Returns the outcome."""
    ctx = service.Ctx(actor_id=e["actor_id"], ip=e.get("ip"), device=e.get("device"), city=e.get("city"),
                      country=e.get("country"), session_id=e.get("session_id"), ts=ts,
                      event_id=f"{e['event_id']}-{run}", labels=e.get("labels"))
    detail = e.get("detail") or {}
    try:
        if e["action"] == "login":
            service.login(store, ctx)
        elif e["action"] == "search":
            service.search(store, ctx, e["resource_id"])
        elif e["action"] == "view":
            service.view(store, ctx, e["resource_id"])
        elif e["action"] == "export":
            service.export(store, ctx, detail.get("query", ""), int(e["records"]), detail.get("fields", []))
        elif e["action"] == "api_get":
            service.partner_claim(store, ctx, e["resource_id"])
        else:
            return "skipped"
        return "allowed"
    except service.PortalError as exc:
        return "denied" if exc.status == 403 else "not_found"


def _detector() -> Callable[[str, datetime], dict[str, Any]] | None:
    try:
        from app.services.detection import process_actor  # T7
    except ImportError:
        return None
    return process_actor


# ---------------------------------------------------------------------------------------------- one run
def run_scenario(sid: str, events: list[dict[str, Any]], store_factory: Callable[[], Any], speed: float,
                 status: dict[str, Any], detect: Callable[[str, datetime], dict] | None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 tick_s: float = TICK_S) -> None:
    """Replay `events` in order. `store_factory()` returns (store, close) for this thread."""
    store, close = store_factory()
    sim_start = _now()
    t0 = clock()
    actors = sorted({e["actor_id"] for e in events})
    last_tick = t0
    status.update(state="running", sim_start=sim_start.isoformat(timespec="seconds"), actors=actors,
                  detection="available" if detect else "unavailable (app.services.detection not on main yet)")

    def tick(final: bool = False) -> None:
        if not detect:
            return
        sim_now = sim_start + timedelta(seconds=(clock() - t0) * speed)
        if final:
            sim_now = max(sim_now, sim_start + timedelta(seconds=events[-1]["offset_s"] + 1))
        for actor in actors:
            try:
                status["last_detection"] = {actor: detect(actor, sim_now)}
            except Exception as exc:  # noqa: BLE001 - keep replaying; show the error on the status page
                status["last_detection"] = {actor: {"error": f"{type(exc).__name__}: {exc}"}}
                log.exception("detection failed for %s", actor)

    try:
        for i, e in enumerate(events):
            if _stop.is_set():
                status["state"] = "stopped"
                return
            due = t0 + e["offset_s"] / speed
            wait = due - clock()
            if wait > 0:
                sleep(wait)
            outcome = send(store, e, sim_start + timedelta(seconds=e["offset_s"]), status["run"])
            status["sent"] = i + 1
            status["outcomes"][outcome] = status["outcomes"].get(outcome, 0) + 1
            if clock() - last_tick >= tick_s:
                tick()
                last_tick = clock()
        tick(final=True)
        status["state"] = "done"
    except Exception as exc:  # noqa: BLE001
        status.update(state="error", error=f"{type(exc).__name__}: {exc}")
        log.exception("replay %s failed", sid)
    finally:
        status["finished_at"] = _now().isoformat(timespec="seconds")
        close()


def _db_store():
    from app.db.session import SessionLocal
    from app.portal.store import DbStore

    db = SessionLocal()
    return DbStore(db), db.close


def start(sid: str, speed: float = DEFAULT_SPEED) -> dict[str, Any]:
    world = _world()
    if sid not in world["scenarios"]:
        raise KeyError(sid)
    with _lock:
        cur = _runs.get(sid)
        if cur and cur["state"] == "running":
            raise RuntimeError(f"{sid} is already running")
        _stop.clear()
        events = world["scenarios"][sid]
        status = {"scenario": sid, "run": f"r{int(time.time())}", "state": "starting", "speed": speed,
                  "events": len(events), "sent": 0, "outcomes": {}, "title": world["manifest"][sid].get("title"),
                  "expected_route": world["manifest"][sid].get("expected_route"),
                  "sim_duration_s": events[-1]["offset_s"], "real_duration_s": round(events[-1]["offset_s"] / speed, 1)}
        _runs[sid] = status
    threading.Thread(target=run_scenario, args=(sid, events, _db_store, speed, status, _detector()),
                     name=f"replay-{sid}", daemon=True).start()
    return status


def status() -> dict[str, Any]:
    return {"runs": _runs, "scenarios": scenario_ids()}


# ---------------------------------------------------------------------------------------------- reset
def reset(db) -> dict[str, Any]:
    """Stop replays, supersede active cases, delete replayed/ad-hoc events, restore seeded actor states."""
    from sqlalchemy import text

    _stop.set()
    deadline = time.monotonic() + 5
    while any(r["state"] == "running" for r in _runs.values()) and time.monotonic() < deadline:
        time.sleep(0.2)
    seeded = _world()["agents"]
    out: dict[str, Any] = {}
    out["cases_superseded"] = db.execute(text(
        "UPDATE cases SET status = 'superseded' WHERE status IN ('open', 'awaiting_review')")).rowcount
    out["events_deleted"] = db.execute(text(
        "DELETE FROM access_events WHERE (labels::jsonb ? 'scenario') OR (detail->>'event_ref') LIKE 'ev-p-%'"
    )).rowcount
    for agent_id, (hr_status, cred) in seeded.items():
        db.execute(text("UPDATE agents SET hr_status = :h, credential_enabled = :c WHERE agent_id = :a"),
                   {"h": hr_status, "c": cred, "a": agent_id})
    out["agents_restored"] = len(seeded)
    out["partner_keys_enabled"] = db.execute(text("UPDATE partner_keys SET enabled = true WHERE NOT enabled")).rowcount
    db.commit()
    with _lock:
        _runs.clear()
    _stop.clear()
    try:
        from app.services.cache import invalidate

        invalidate()  # dashboard numbers
    except Exception:  # noqa: BLE001
        pass
    return out
