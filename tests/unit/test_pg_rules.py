"""Detectors A1, A3, A4 (T5) and I1, P1, P2, P3, A2 (T6): small in-memory fixtures per signal, then the pg_small
scenarios (S1, S1b, S1c, S1d, S5) checked against tests/fixtures/pg_small/manifest.json. No database."""

import ast
import itertools
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.ingest import pg_rules
from app.ingest.pg_rules import (
    AccessEvent,
    AgentProfile,
    Baseline,
    ContextRecord,
    PartnerProfile,
    build_scope,
    detect,
    records_and_tier,
)
from app.services import risk

NOW = datetime(2026, 11, 20, 8, 0)  # 13:30 IST, inside 10-19
AGENT = AgentProfile(agent_id="AG-1", usual_start_hour=10, usual_end_hour=19, home_city="Pune",
                     known_devices=frozenset({"dv-1"}), manager_id="MG-1")
_ids = itertools.count(1)


def ev(action="view", ph=None, *, ts=None, minutes_ago=5, outcome="allowed", tier="T2", records=1, device="dv-1",
       city="Pune", actor="AG-1", resource_type=None, resource_id=None):
    if resource_type is None:
        resource_type = {"export": "export_file", "login": "session", "search": "search"}.get(action, "policyholder")
    return AccessEvent(id=next(_ids), ts=ts or NOW - timedelta(minutes=minutes_ago), actor_id=actor,
                       actor_type="agent", action=action, resource_type=resource_type,
                       resource_id=resource_id or ph or f"r-{action}", policyholder_id=ph, tier=tier,
                       records=records, outcome=outcome, device=device, city=city)


def views(prefix, n, **kw):
    return [ev("view", f"{prefix}{i}", **kw) for i in range(n)]


def scope_for(portfolios=None, reports=(), records=(), agent_id="AG-1"):
    portfolios = {"AG-1": {"PH-own"}, **(portfolios or {})}
    return build_scope(agent_id, portfolios, reports, records)


def run(events, now=NOW, scope=None, agent=AGENT):
    return detect("AG-1", "agent", events, now, agent=agent, scope=scope if scope is not None else scope_for())


# ------------------------------------------------------------------ A1


def test_a1_fires_at_ten_distinct_out_of_scope_policyholders():
    det = run(views("PH-x", 10))
    assert det.signals["A1"]["confidence"] == 0.9
    assert det.signals["A1"]["detail"] == {"out_of_scope_policyholders": 10}


def test_a1_does_not_fire_at_nine():
    assert "A1" not in run(views("PH-x", 9)).signals


def test_a1_counts_distinct_policyholders_not_events():
    assert "A1" not in run([ev("view", "PH-x") for _ in range(30)]).signals


def test_a1_own_and_team_portfolios_are_in_scope():
    team = {f"PH-t{i}" for i in range(12)}
    scope = scope_for(portfolios={"AG-2": team}, reports=["AG-2"])  # AG-1 manages AG-2
    assert "A1" not in run(views("PH-t", 12), scope=scope).signals
    assert "A1" not in run([ev("view", "PH-own") for _ in range(12)]).signals


def test_a1_transfer_naming_the_agent_counts_only_while_valid():
    theirs = {f"PH-y{i}" for i in range(12)}
    valid = ContextRecord("transfer", "AG-9", "AG-1", NOW - timedelta(days=1), NOW + timedelta(days=1))
    expired = ContextRecord("transfer", "AG-9", "AG-1", NOW - timedelta(days=3), NOW - timedelta(hours=2))
    other = ContextRecord("transfer", "AG-9", "AG-7", NOW - timedelta(days=1), NOW + timedelta(days=1))
    for record, fires in [(valid, False), (expired, True), (other, True)]:
        scope = scope_for(portfolios={"AG-9": theirs}, records=[record])
        assert ("A1" in run(views("PH-y", 12), scope=scope).signals) is fires, record


def test_a1_servicing_assignment_and_approval_also_grant_scope():
    theirs = {f"PH-y{i}" for i in range(12)}
    for kind in ("servicing_assignment", "approval"):
        scope = scope_for(portfolios={"AG-9": theirs}, records=[ContextRecord(kind, "AG-9", "AG-1")])
        assert "A1" not in run(views("PH-y", 12), scope=scope).signals, kind


def test_a1_tickets_and_leave_put_nothing_in_scope():
    theirs = {f"PH-y{i}" for i in range(12)}
    records = [ContextRecord("ticket", "AG-9", "AG-1"), ContextRecord("leave", "AG-9", None)]
    scope = scope_for(portfolios={"AG-9": theirs}, records=records)
    assert "A1" in run(views("PH-y", 12), scope=scope).signals


def test_a1_ignores_denied_reads_and_events_outside_the_window():
    assert "A1" not in run(views("PH-x", 12, outcome="denied")).signals
    assert "A1" not in run(views("PH-x", 12, minutes_ago=61)).signals


# ------------------------------------------------------------------ A3


@pytest.mark.parametrize("records,tier,outcome,fires", [
    (200, "T2", "allowed", True),
    (199, "T2", "allowed", False),
    (5, "T1", "allowed", True),
    (5000, "T2", "denied", False),
])
def test_a3_bulk_export(records, tier, outcome, fires):
    det = run([ev("export", records=records, tier=tier, outcome=outcome)])
    assert ("A3" in det.signals) is fires
    if fires:
        assert det.signals["A3"]["confidence"] == 0.8
        assert det.signals["A3"]["detail"]["max_rows"] == records


# ------------------------------------------------------------------ A4


def test_a4_off_hours_uses_ist():
    night = datetime(2026, 11, 20, 18, 8)  # 23:38 IST
    det = run([ev(ts=night)], now=night + timedelta(minutes=5))
    assert det.signals["A4"]["detail"]["fired"] == ["off_hours"]
    # 05:00 UTC is 10:30 IST: inside hours, although hour 5 would be outside 10-19 in UTC.
    morning = datetime(2026, 11, 20, 5, 0)
    assert "A4" not in run([ev(ts=morning)], now=morning + timedelta(minutes=5)).signals
    early = datetime(2026, 11, 20, 4, 0)  # 09:30 IST
    assert "A4" in run([ev(ts=early)], now=early + timedelta(minutes=5)).signals


def test_a4_new_device_and_new_city():
    det = run([ev(device="dv-new")])
    assert det.signals["A4"]["detail"] == {"fired": ["new_device"], "new_devices": ["dv-new"]}
    det = run([ev(city="Lucknow")])
    assert det.signals["A4"]["detail"] == {"fired": ["new_city"], "new_cities": ["Lucknow"]}


def test_a4_missing_device_or_city_never_counts():
    assert "A4" not in run([ev(device=None, city=None)]).signals


def test_a4_fires_once_with_every_reason_in_detail():
    night = datetime(2026, 11, 20, 18, 8)
    det = run([ev(ts=night, device="dv-new", city="Lucknow"), ev(ts=night, device="dv-2")], now=night)
    assert det.signals["A4"]["confidence"] == 0.4
    assert det.signals["A4"]["detail"]["fired"] == ["off_hours", "new_device", "new_city"]
    assert det.signals["A4"]["detail"]["new_devices"] == ["dv-2", "dv-new"]


@pytest.mark.parametrize("hour,start,end,inside", [
    (10, 10, 19, True), (18, 10, 19, True), (19, 10, 19, False), (9, 10, 19, False),
    (23, 22, 6, True), (5, 22, 6, True), (12, 22, 6, False), (3, 0, 0, True),
])
def test_usual_hours_window(hour, start, end, inside):
    assert pg_rules._within_usual_hours(hour, start, end) is inside


# ------------------------------------------------------------------ I1


def test_i1_fires_for_a_terminated_agent_with_an_allowed_event():
    terminated = AgentProfile("AG-1", 10, 19, "Pune", frozenset({"dv-1"}), hr_status="terminated")
    det = run([ev("view", "PH-own")], agent=terminated)
    assert det.signals["I1"]["confidence"] == 0.95
    assert det.signals["I1"]["detail"] == {"hr_status": "terminated", "credential_enabled": True, "allowed_events": 1}
    assert det.risk >= 60 and det.band == "high"  # the floor


def test_i1_does_not_fire_on_denied_only_events():
    suspended = AgentProfile("AG-1", 10, 19, "Pune", frozenset({"dv-1"}), hr_status="suspended",
                             credential_enabled=False)  # after PB1: every attempt is a 403
    assert "I1" not in run([ev("login", outcome="denied"), ev("view", "PH-own", outcome="denied")],
                           agent=suspended).signals


def test_i1_fires_for_a_disabled_credential_and_not_for_an_active_agent():
    disabled = AgentProfile("AG-1", 10, 19, "Pune", frozenset({"dv-1"}), credential_enabled=False)
    assert "I1" in run([ev("login", tier="T3", records=0)], agent=disabled).signals
    assert "I1" not in run([ev("view", "PH-own")]).signals


# ------------------------------------------------------------------ partner keys: P1, P2, P3, I1

KEY = PartnerProfile("PK-1", enabled=True, known_ips=frozenset({"203.0.113.10"}),
                     assigned_claims=frozenset({"CL-100", "CL-205", "CL-317"}))


def claim(cid, *, outcome="allowed", ip="203.0.113.10", minutes_ago=5):
    return AccessEvent(id=next(_ids), ts=NOW - timedelta(minutes=minutes_ago), actor_id="PK-1",
                       actor_type="partner_key", action="api_get", resource_type="claim", resource_id=cid, tier="T1",
                       records=1 if outcome == "allowed" else 0, outcome=outcome, channel="api", ip=ip)


def run_key(events, partner=KEY):
    return detect("PK-1", "partner_key", events, NOW, partner=partner)


def test_assigned_claims_from_the_known_ip_fire_nothing():
    assert run_key([claim("CL-100"), claim("CL-205"), claim("CL-317")]).signals == {}


def test_p1_unassigned_claim_returned():
    det = run_key([claim("CL-100"), claim("CL-999")])
    assert det.signals["P1"] == {"confidence": 0.9, "detail": {"unassigned_claims": 1}}
    assert "P1" not in run_key([claim("CL-999", outcome="not_found"), claim("CL-998", outcome="denied")]).signals


@pytest.mark.parametrize("ids,failed,fires", [
    ([f"CL-{1000 + i}" for i in range(20)], 0, True),       # 20 fetches, every id steps by 1
    ([f"CL-{1000 + i}" for i in range(19)], 0, False),      # 19: below the minimum
    ([f"CL-{1000 + 7 * i}" for i in range(25)], 0, False),  # not sequential, all found
    ([f"CL-{1000 + 7 * i}" for i in range(25)], 10, True),  # 40% not found
    ([f"CL-{1000 + 7 * i}" for i in range(30)], 9, False),  # exactly 30% is not above 30%
])
def test_p2_enumeration(ids, failed, fires):
    events = [claim(cid, outcome="not_found" if i < failed else "allowed") for i, cid in enumerate(ids)]
    det = run_key(events, partner=PartnerProfile("PK-1", known_ips=KEY.known_ips, assigned_claims=frozenset(ids)))
    assert ("P2" in det.signals) is fires
    if fires:
        assert det.signals["P2"]["confidence"] == 0.8 and det.signals["P2"]["detail"]["fetches"] == len(ids)


def test_p3_new_origin_and_missing_ip():
    det = run_key([claim("CL-100", ip="198.51.100.77")])
    assert det.signals["P3"] == {"confidence": 0.6, "detail": {"new_ips": ["198.51.100.77"]}}
    assert "P3" not in run_key([claim("CL-100", ip=None)]).signals


def test_s2_shape_fires_p1_p2_p3_and_scores_critical():
    events = [claim(f"CL-{5000 + i}", ip="198.51.100.77", outcome="not_found" if i % 3 else "allowed")
              for i in range(420)]
    det = run_key(events)
    assert set(det.signals) == {"P1", "P2", "P3"}
    assert det.band == "critical" and det.event_ids[0] == events[0].id  # P1's hits come first


def test_i1_for_a_disabled_partner_key_needs_an_allowed_request():
    disabled = PartnerProfile("PK-1", enabled=False, known_ips=KEY.known_ips, assigned_claims=KEY.assigned_claims)
    assert run_key([claim("CL-100")], partner=disabled).signals["I1"]["detail"]["key_enabled"] is False
    assert "I1" not in run_key([claim("CL-100", outcome="denied")], partner=disabled).signals  # after PB2


# ------------------------------------------------------------------ A2

NORMAL_HOURS = (2, 3, 3, 4, 4, 4, 5, 5, 6, 7) * 10  # an agent who opens 3-6 records an hour
PEER_HOURS = (3, 4, 5, 6, 7, 8, 9) * 10             # p95 = 9


@pytest.mark.parametrize("records,baseline,fires", [
    (130, Baseline(NORMAL_HOURS, 30, PEER_HOURS), True),           # S1b-like: far above own and 3x peers
    (40, Baseline(NORMAL_HOURS, 30, (10, 15) * 20), False),        # own z is high, but not above 3x peer p95 (45)
    (130, Baseline((100, 120, 140, 110) * 10, 30, PEER_HOURS), False),  # a heavy user: z < 4
    (130, Baseline(NORMAL_HOURS, 3, PEER_HOURS), True),            # 3 days of history: the peer test alone
    (20, Baseline(NORMAL_HOURS, 3, PEER_HOURS), False),            # ... and it fails at 20 <= 27
    (130, Baseline(NORMAL_HOURS, 30, ()), True),                   # no peer data: the own test alone
    (130, Baseline((), 0, ()), False),                             # nothing to compare with
])
def test_a2_volume_spike(records, baseline, fires):
    found = pg_rules.a2_volume_spike(records, baseline)
    assert (found is not None) is fires
    if fires:
        assert found["confidence"] == 0.7 and found["detail"]["records"] == records


def test_a2_guards_a_zero_mad():
    flat = Baseline((4,) * 50, 30, ())  # MAD 0: the scale floors at 1 record
    assert pg_rules.a2_volume_spike(10, flat)["detail"]["z"] == pytest.approx(4.0, abs=0.1)
    assert pg_rules.a2_volume_spike(9, flat) is None


def test_baseline_from_history_counts_hours_and_calendar_days():
    day = datetime(2026, 11, 10, 5, 0)  # 10:30 IST
    own = [ev("view", f"PH-{d}-{i}", ts=day + timedelta(days=d, minutes=i)) for d in (0, 1, 5) for i in range(3)]
    peers = [ev("view", f"PH-p{i}", ts=day + timedelta(minutes=i), actor="AG-2") for i in range(7)]
    base = Baseline.from_history(own, peers)
    assert base.own_hourly == (3, 3, 3) and base.peer_hourly == (7,)
    assert base.own_days == 6  # 10 Nov to 15 Nov: a gap does not shorten the history


def test_detect_runs_a2_for_agents_given_a_baseline():
    own_reads = [ev("view", f"PH-t{i}") for i in range(130)]  # in the agent's own portfolio: no A1
    scope = scope_for(portfolios={"AG-1": {f"PH-t{i}" for i in range(130)}})
    assert "A2" not in detect("AG-1", "agent", own_reads, NOW, agent=AGENT, scope=scope).signals
    det = detect("AG-1", "agent", own_reads, NOW, agent=AGENT, scope=scope,
                 baseline=Baseline(NORMAL_HOURS, 30, PEER_HOURS))
    # A2 alone on 130 T2 records is 39.1: logged, like D3's renewal campaign (39).
    assert set(det.signals) == {"A2"}
    assert (det.risk, det.band) == (pytest.approx(39.1, abs=0.5), "low")


# ------------------------------------------------------------------ output


def test_quiet_window_gives_no_signals_and_zero_risk():
    det = run([ev("view", "PH-own"), ev("login")])
    assert det.signals == {} and not det.fired
    assert (det.risk, det.band, det.event_ids) == (0.0, "low", [])


def test_records_and_tier():
    events = [ev("view", "PH-1"), ev("view", "PH-1"), ev("view", "PH-2", tier="T1"), ev("login", tier="T3"),
              ev("search", records=0, tier="T3"), ev("view", "PH-3", outcome="denied", tier="T1")]
    assert records_and_tier(events) == (2, "T1")
    assert records_and_tier([*events, ev("export", records=50)]) == (50, "T1")  # a bigger export sets the floor
    assert records_and_tier([ev("login", tier="T3")]) == (0, None)


def test_evidence_ids_put_the_export_first_and_stop_at_200():
    export = ev("export", records=1200, tier="T1")
    det = run([*views("PH-x", 300), export])
    assert det.event_ids[0] == export.id
    assert len(det.event_ids) == pg_rules.MAX_EVENT_IDS == len(set(det.event_ids))


def test_other_actors_events_are_ignored():
    assert run(views("PH-x", 12, actor="AG-2")).signals == {}


def test_risk_comes_from_the_risk_function():
    det = run([*views("PH-x", 130), ev("export", records=500, tier="T2")])
    assert (det.risk, det.band) == risk.score({"A1": 0.9, "A3": 0.8}, "T2", 500, "agent")


def test_window_is_iso_for_raw_json():
    det = run([])
    assert det.window == {"start": "2026-11-20T07:00:00", "end": "2026-11-20T08:00:00"}


def test_labels_never_reach_the_detectors():
    row = {"id": 7, "ts": "2026-11-20T07:55:00", "actor_id": "AG-1", "actor_type": "agent", "action": "view",
           "resource_type": "policyholder", "resource_id": "PH-1", "labels": {"is_attack": True, "scenario": "S1"},
           "detail": {"event_ref": "ev-1"}, "country": "IN"}
    event = AccessEvent.from_row(row)
    assert not hasattr(event, "labels") and not hasattr(event, "detail")
    assert event.ts == datetime(2026, 11, 20, 7, 55)


def test_module_does_not_import_the_unix_only_alerts_module():
    tree = ast.parse(Path(pg_rules.__file__).read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert "app.ingest.alerts" not in imported
    assert "labels" not in {f for f in AccessEvent.__dataclass_fields__}


# ------------------------------------------------------------------ pg_small fixture: the scenarios

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "pg_small"
NOT_BUILT = {"A5"}  # in S1's manifest entry, but not built today
EXPECTED_TIER = {"S1": "T1", "S1b": "T2", "S1c": "T2", "S1d": "T2", "S5": "T2"}
SCENARIO_ACTORS = {"S1": "AG-1147", "S1b": "AG-1033", "S1c": "AG-1088", "S1d": "AG-1120", "S5": "AG-0577"}


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def world():
    agents = {a["agent_id"]: a for a in json.loads((FIXTURE / "agents.json").read_text(encoding="utf-8"))}
    portfolios: dict[str, set[str]] = defaultdict(set)
    for row in _jsonl(FIXTURE / "portfolios.jsonl"):
        portfolios[row["agent_id"]].add(row["policyholder_id"])
    records = [ContextRecord.from_row(r) for r in json.loads((FIXTURE / "context_records.json").read_text("utf-8"))]
    rows = _jsonl(FIXTURE / "history.jsonl")
    for path in sorted((FIXTURE / "scenarios").glob("*.jsonl")):
        rows += _jsonl(path)
    # The database assigns integer ids; do the same here.
    events = [AccessEvent.from_row({**row, "id": i}) for i, row in enumerate(rows, start=1)]
    manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))["scenarios"]
    return {"agents": agents, "portfolios": portfolios, "records": records, "events": events, "manifest": manifest}


def detect_scenario(world, sid):
    """As detection.Store does: own and branch-peer history from the 30 days before the window."""
    m = world["manifest"][sid]
    actor, now = m["actor"], datetime.fromisoformat(m["end"])
    reports = [a for a, row in world["agents"].items() if row.get("manager_id") == actor]
    scope = build_scope(actor, world["portfolios"], reports, world["records"])
    end = now - pg_rules.WINDOW
    lookback = [e for e in world["events"] if end - pg_rules.A2_LOOKBACK <= e.ts < end]
    branch = world["agents"][actor]["branch"]
    peers = {a for a, row in world["agents"].items() if row["branch"] == branch and a != actor}
    baseline = Baseline.from_history((e for e in lookback if e.actor_id == actor),
                                     (e for e in lookback if e.actor_id in peers))
    return detect(actor, "agent", world["events"], now, agent=AgentProfile.from_row(world["agents"][actor]),
                  scope=scope, baseline=baseline)


@pytest.mark.parametrize("sid", list(SCENARIO_ACTORS))
def test_scenario_fires_the_expected_signals(world, sid):
    m = world["manifest"][sid]
    assert m["actor"] == SCENARIO_ACTORS[sid]
    det = detect_scenario(world, sid)
    assert set(det.signals) == set(m["expected_signals"]) - NOT_BUILT
    assert det.n_records == m["records"]
    assert det.tier == EXPECTED_TIER[sid]


@pytest.mark.parametrize("sid", list(SCENARIO_ACTORS))
def test_scenario_score_matches_the_manifest(world, sid):
    # S1 89, S1b 54, S1c 54, S1d 55, S5 60 (I1's floor over a formula value of 50).
    det = detect_scenario(world, sid)
    assert det.risk == pytest.approx(world["manifest"][sid]["expected_score"], abs=0.5)


def test_s1_details_and_evidence(world):
    det = detect_scenario(world, "S1")
    a4 = det.signals["A4"]["detail"]
    assert a4["fired"] == ["off_hours", "new_device", "new_city"]
    assert a4["new_devices"] == ["dv-9f2c"] and a4["new_cities"] == ["Lucknow"]
    assert det.signals["A3"]["detail"]["max_rows"] == 1200
    assert det.signals["A1"]["detail"]["out_of_scope_policyholders"] == 1840
    first = next(e for e in world["events"] if e.id == det.event_ids[0])
    assert first.action == "export"
    assert len(det.event_ids) == 200


def test_cover_scenarios_are_out_of_scope_because_tickets_do_not_grant_access(world):
    # S1b's ticket TKT-4471 names Anita, but only the AI judge may accept it; the rules still raise A1.
    for sid in ("S1b", "S1c", "S1d"):
        det = detect_scenario(world, sid)
        assert det.signals["A1"]["detail"]["out_of_scope_policyholders"] == world["manifest"][sid]["records"]
