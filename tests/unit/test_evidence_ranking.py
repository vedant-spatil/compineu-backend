"""evidence.top_events must carry the story of the alert (the export and the reads outside the boundary), not the oldest
events of the 48-hour window. In the real S1 run every view had one record, so the old order (records desc, id asc) showed
the previous day's normal history."""

from datetime import UTC, datetime, timedelta

from app.orchestration import assembly, prompts
from app.services.pg_data import AccessEvent

DAY = datetime(2026, 11, 20, 18, 8, tzinfo=UTC)


def _ev(eid: int, ts: datetime, rid: str, *, action: str = "view", records: int = 1, outcome: str = "allowed",
        tier: int = 1) -> AccessEvent:
    return AccessEvent(id=eid, ts=ts, actor_id="AG-1147", actor_type="agent", action=action,
                       resource_type="policyholder" if action == "view" else "export_file", resource_id=rid, tier=tier,
                       records=records, outcome=outcome, channel="portal")


def _s1_like() -> tuple[list[AccessEvent], set[str]]:
    portfolio = {f"PH-1{i:04d}" for i in range(250)}
    events = [_ev(100 + i, DAY - timedelta(days=1) + timedelta(minutes=i), f"PH-1{i:04d}", tier=2) for i in range(60)]  # normal day
    events += [_ev(10_000 + i, DAY + timedelta(seconds=1.5 * i), f"PH-2{i:04d}") for i in range(1840)]  # the burst, out of portfolio
    events.append(_ev(20_000, DAY + timedelta(minutes=46), "EXP-1", action="export", records=1200))
    events.append(_ev(20_001, DAY + timedelta(minutes=2), "PH-29999", outcome="denied"))
    return sorted(events, key=lambda e: (e.ts, e.id)), portfolio


def test_the_export_and_the_burst_lead_the_top_events_and_history_is_left_out():
    events, portfolio = _s1_like()
    ev = assembly.build_evidence(events, portfolio, [])
    top = ev["top_events"]
    assert len(top) == assembly.TOP_EVENTS
    assert top[0]["event_id"] == 20_000 and top[0]["action"] == "export" and top[0]["records"] == 1200
    burst = top[1:]
    assert [e["event_id"] for e in burst] == list(range(10_000, 10_000 + assembly.TOP_EVENTS - 1))  # the first reads, in time order
    assert all(e["in_scope"] is False and e["ts"] >= DAY.isoformat() for e in burst)
    assert not any(100 <= e["event_id"] < 160 for e in top)  # none of the previous day's normal history
    assert all(isinstance(e["event_id"], int) for e in top) and all(isinstance(i, int) for i in ev["event_ids"])
    assert {e["event_id"] for e in top} <= set(ev["event_ids"])
    # the counts are unchanged by the ranking
    assert ev["out_of_scope"] == {"events": 1840, "records": 1840, "distinct_policyholders": 1840}
    assert ev["export"]["rows"] == 1200 and ev["in_scope"]["events"] == 60 and ev["denied"] == 1


def test_with_an_unknown_boundary_every_allowed_read_is_the_story_and_stays_in_time_order():
    events, _ = _s1_like()
    top = assembly.build_evidence(events, None, [])["top_events"]
    assert top[0]["action"] == "export"
    ts = [e["ts"] for e in top[1:]]
    assert ts == sorted(ts) and top[1]["event_id"] == 100  # nothing is known to be in scope, so the oldest read comes first


def test_without_anything_outside_the_boundary_the_biggest_events_still_come_first():
    portfolio = {f"PH-{i}" for i in range(30)}
    events = [_ev(i, DAY + timedelta(minutes=i), f"PH-{i}", records=i + 1) for i in range(30)]
    top = assembly.build_evidence(events, portfolio, [])["top_events"]
    assert [e["records"] for e in top] == sorted((e["records"] for e in top), reverse=True)
    assert top[0]["event_id"] == 29


def test_the_prompts_name_the_time_zones_and_carry_no_names():
    for system in (prompts.REPORT_SYSTEM, prompts.CLASSIFY_SYSTEM):
        assert "UTC" in system and "IST" in system and "UTC+5:30" in system and "23:38 IST" in system
    assert "never call a UTC time IST" in prompts.REPORT_SYSTEM
