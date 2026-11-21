"""Replay engine: events go through the portal functions in order, on a shifted clock, with detection ticks."""
import json
from datetime import datetime
from pathlib import Path

from app.portal import replay
from app.portal.store import MemoryStore

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "pg_small"


def _events(sid: str) -> list[dict]:
    with open(FIXTURE / "scenarios" / f"{sid}.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


def _run(sid: str, store: MemoryStore, detect=None) -> dict:
    clock = FakeClock()
    status = {"run": "r1", "outcomes": {}, "sent": 0}
    replay.run_scenario(sid, _events(sid), lambda: (store, lambda: None), 60.0, status, detect,
                        sleep=clock.sleep, clock=clock)
    return status


def test_s1_goes_through_the_portal_in_order_on_a_shifted_clock() -> None:
    store = MemoryStore.from_dir(FIXTURE)
    calls: list[tuple[str, datetime]] = []
    status = _run("S1", store, lambda actor, now: calls.append((actor, now)) or {"action": "none"})
    events = _events("S1")
    assert status["state"] == "done" and status["sent"] == len(events) == len(store.events)
    assert status["outcomes"] == {"allowed": len(events)}
    recorded = store.events
    assert [e["action"] for e in recorded] == [e["action"] for e in events]
    assert recorded[-1]["action"] == "export" and recorded[-1]["records"] == 1200 and recorded[-1]["tier"] == "T1"
    assert recorded[0]["event_id"] == "ev-s1-00001-r1" and recorded[0]["labels"]["scenario"] == "S1"
    span = (datetime.fromisoformat(recorded[-1]["ts"]) - datetime.fromisoformat(recorded[0]["ts"])).total_seconds()
    assert span == events[-1]["offset_s"]                      # simulated spacing kept
    assert calls and all(a == "AG-1147" for a, _ in calls)     # detection ticked for the actor
    assert calls[-1][1] >= datetime.fromisoformat(recorded[-1]["ts"])  # final tick sees the export


def test_suspended_agent_is_refused_and_replay_continues() -> None:
    store = MemoryStore.from_dir(FIXTURE)
    store.agents["AG-1088"]["credential_enabled"] = False      # after PB1
    status = _run("S1c", store)
    assert status["state"] == "done" and status["outcomes"] == {"denied": len(_events("S1c"))}
    assert status["detection"].startswith("unavailable")


def test_detection_errors_do_not_stop_the_replay() -> None:
    store = MemoryStore.from_dir(FIXTURE)

    def boom(actor, now):
        raise RuntimeError("detector broke")

    status = _run("S5", store, boom)
    assert status["state"] == "done" and "detector broke" in status["last_detection"]["AG-0577"]["error"]
