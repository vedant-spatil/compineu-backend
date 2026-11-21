"""Detection entry point (T7): the decision logic over an in-memory store, the pending-rerun follow-up in
services/cases.py over a fake session, and the clock and labels rules. No database."""

import ast
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

import app.db.session as db_session
from app.db import models
from app.ingest import pg_rules
from app.services import cases as case_service
from app.services import detection

NOW = datetime(2026, 11, 20, 18, 46)  # simulated clock (S1's last tick); 00:16 IST
AGENT = pg_rules.AgentProfile(agent_id="AG-1147", usual_start_hour=10, usual_end_hour=19, home_city="Pune",
                              known_devices=frozenset({"dv-76f1"}))
SCOPE = pg_rules.build_scope("AG-1147", {"AG-1147": {"PH-own"}}, [], [])
_ids = iter(range(1, 1_000_000))


def ev(action="view", ph=None, *, minutes_ago=10, tier="T1", records=1, device="dv-9f2c", city="Lucknow"):
    resource_type = {"export": "export_file"}.get(action, "policyholder")
    return pg_rules.AccessEvent(id=next(_ids), ts=NOW - timedelta(minutes=minutes_ago), actor_id="AG-1147",
                                actor_type="agent", action=action, resource_type=resource_type,
                                resource_id=ph or f"r-{action}", policyholder_id=ph, tier=tier, records=records,
                                device=device, city=city)


def s1_reads(n=1840, **kw):
    return [ev("view", f"PH-x{i}", **kw) for i in range(n)]


def make_alert(alert_id, rules, band, txn_ids=(1, 2), window_end=NOW - timedelta(minutes=1)):
    return SimpleNamespace(id=alert_id, account_id="AG-1147", ts=NOW - timedelta(minutes=30), rules=list(rules),
                           risk_score=0.84, is_laundering=None, amount=0,
                           raw_json={"band": band, "txn_ids": list(txn_ids),
                                     "window": {"start": "x", "end": window_end.isoformat()}})


class FakeStore:
    """The Store interface over plain objects. Records what process() asked it to do."""

    def __init__(self, events, *, decided=None, active=None, alerts=(), refuse_rerun=False, evidence=True):
        self.events, self.decided, self.active = events, decided, active
        self.alerts = {a.id: a for a in alerts}
        self.refuse_rerun = refuse_rerun
        self.evidence = evidence  # False: a reset deleted the decided case's events
        self.audits, self.reruns, self.started, self.new_alerts = [], [], [], []
        self.commits = self.rollbacks = 0
        self.cutoff = "not asked"
        self._next = 500

    def last_decided(self, actor_id):
        return self.decided

    def evidence_exists(self, event_ids):
        return self.evidence and bool(event_ids)

    def inputs(self, actor_id, cutoff, now):
        self.cutoff = cutoff  # the database query keeps only events after the cutoff; do the same
        events = [e for e in self.events if cutoff is None or e.ts > cutoff]
        return detection.Inputs("agent", events, AGENT, SCOPE)

    def active_case(self, actor_id):
        return self.active

    def alert(self, alert_id):
        return self.alerts[alert_id]

    def reusable_alert(self, actor_id, now):
        return None

    def new_alert(self, now):
        self._next += 1
        alert = SimpleNamespace(id=self._next, ts=now, rules=[], raw_json={}, risk_score=0.0)
        self.alerts[alert.id] = alert
        self.new_alerts.append(alert)
        return alert

    def is_attack(self, event_ids):
        return True

    def start_case(self, alert):
        self._next += 1
        case = SimpleNamespace(id=self._next, alert_id=alert.id, status="open", state={})
        self.started.append(case)
        return case

    def prepare_rerun(self, case_id, reason):
        if self.refuse_rerun:
            raise case_service.RerunRefused("the actor already has another active case")
        case = self.active
        attempt = int(case.state.get("attempt", 0)) + 1
        case.state = {**{k: v for k, v in case.state.items() if k != "rerun_pending"}, "attempt": attempt}
        case.status = "open"
        alert = self.alerts[case.alert_id]
        args = {"case_id": case.id, "txn_ids": list(alert.raw_json["txn_ids"]), "attempt": attempt}
        self.reruns.append((reason, args))
        return args

    def audit(self, case_id, kind, payload):
        self.audits.append((case_id, kind, payload))
        self.commits += 1

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


# ------------------------------------------------------------------ 1. escalation trigger


@pytest.mark.parametrize("old_band,old_rules,new_band,new_signals,expected", [
    ("high", ["A1", "A4"], "critical", ["A1", "A4"], True),         # band went up
    ("critical", ["A1", "A4"], "critical", ["A1", "A3", "A4"], True),  # same band, a new signal (S1's export)
    ("critical", ["A1", "A3", "A4"], "critical", ["A1", "A3", "A4"], False),
    ("critical", ["A1", "A3", "A4"], "high", ["A1"], False),        # lower and nothing new
])
def test_should_escalate(old_band, old_rules, new_band, new_signals, expected):
    assert detection.should_escalate(old_band, old_rules, new_band, new_signals) is expected


def test_s1_export_at_critical_reruns_an_awaiting_review_case_with_the_export_first():
    export = ev("export", records=1200, minutes_ago=1)
    alert = make_alert(1, ["A1", "A4"], "critical")
    case = SimpleNamespace(id=10, alert_id=1, status="awaiting_review", state={"attempt": 0})
    store = FakeStore([*s1_reads(), export], active=case, alerts=[alert])

    result, run_args = detection.process(store, "AG-1147", NOW)

    assert result["action"] == "escalated" and result["band"] == "critical"
    (_, kind, payload), = store.audits
    assert kind == "risk_escalated" and payload["signals"] == ["A3"]
    assert payload["old"]["band"] == payload["new"]["band"] == "critical"
    assert store.reruns[0][0] == "risk_escalated"
    assert run_args["txn_ids"][0] == export.id and run_args["attempt"] == 1
    assert alert.rules == ["A1", "A3", "A4"] and alert.raw_json["txn_ids"][0] == export.id


def test_s1_export_while_the_workflow_runs_sets_rerun_pending():
    alert = make_alert(1, ["A1", "A4"], "critical")
    case = SimpleNamespace(id=10, alert_id=1, status="open", state={"attempt": 0})
    store = FakeStore([*s1_reads(), ev("export", records=1200, minutes_ago=1)], active=case, alerts=[alert])

    result, run_args = detection.process(store, "AG-1147", NOW)

    assert result["action"] == "escalated" and run_args is None
    assert case.state["rerun_pending"] is True and store.reruns == []


def test_no_new_signal_and_same_band_is_unchanged():
    alert = make_alert(1, ["A1", "A3", "A4"], "critical")
    case = SimpleNamespace(id=10, alert_id=1, status="awaiting_review", state={})
    store = FakeStore([*s1_reads(), ev("export", records=1200, minutes_ago=1)], active=case, alerts=[alert])

    result, run_args = detection.process(store, "AG-1147", NOW)

    assert result["action"] == "unchanged" and run_args is None
    assert store.audits == [] and store.reruns == []


# ------------------------------------------------------------------ 2. rerun_pending: the run thread follows up


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeSession:
    """Enough of a SQLAlchemy session for cases.prepare_rerun and take_pending_rerun."""

    def __init__(self, case, alert, commit_error=None):
        self.case, self.alert, self.commit_error = case, alert, commit_error
        self.commits = self.rollbacks = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement):
        return _Result(self.case)

    def get(self, model, key):
        return self.alert if model is models.Alert else self.case

    def commit(self):
        if self.commit_error is not None:
            raise self.commit_error
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def fake_db(monkeypatch):
    case = SimpleNamespace(id=10, alert_id=1, account_id="AG-1147", status="open", state={"attempt": 0})
    alert = SimpleNamespace(id=1, account_id="AG-1147", ts=NOW, rules=["A1", "A4"], risk_score=0.84,
                            raw_json={"txn_ids": [1, 2]})
    session = FakeSession(case, alert)
    events = []
    monkeypatch.setattr(db_session, "SessionLocal", lambda: session)
    monkeypatch.setattr(case_service, "write_event", lambda db, case_id, node, kind, payload=None:
                        events.append((node, kind, payload)))
    monkeypatch.setattr(case_service, "invalidate", lambda: None)
    return SimpleNamespace(case=case, alert=alert, session=session, events=events)


def test_the_run_thread_reruns_with_the_current_txn_ids_until_the_flag_stays_clear(fake_db, monkeypatch):
    runs = []

    def fake_run_case(case_id, alert_id, account_id, alert_ts, rules, risk, txn_ids, attempt=0):
        runs.append((attempt, list(txn_ids)))
        if attempt == 0:  # detection escalates while the first run is going: S1's export arrives
            fake_db.case.state = {**fake_db.case.state, "rerun_pending": True}
            fake_db.alert.raw_json = {"txn_ids": [999, 1, 2]}
        fake_db.case.status = "awaiting_review"  # the workflow stops at the human review

    monkeypatch.setattr(case_service, "run_case", fake_run_case)
    case_service.run_case_with_followups(10, 1, "AG-1147", NOW.isoformat(), ["A1", "A4"], 0.84, [1, 2], 0)

    assert runs == [(0, [1, 2]), (1, [999, 1, 2])]
    assert "rerun_pending" not in fake_db.case.state and fake_db.case.state["attempt"] == 1
    assert fake_db.events == [("workflow", "rerun", {"attempt": 1, "by_user_id": None, "reason": "rerun_pending"})]


@pytest.mark.parametrize("status,state", [("failed", {"rerun_pending": True}), ("awaiting_review", {})])
def test_no_follow_up_without_the_flag_or_off_review(fake_db, status, state):
    fake_db.case.status, fake_db.case.state = status, state
    assert case_service.take_pending_rerun(10) is None
    assert fake_db.events == []


def test_a_later_detection_call_also_takes_a_pending_flag():
    alert = make_alert(1, ["A1", "A3", "A4"], "critical", txn_ids=(7, 8))
    case = SimpleNamespace(id=10, alert_id=1, status="awaiting_review", state={"rerun_pending": True})
    store = FakeStore([*s1_reads(), ev("export", records=1200, minutes_ago=1)], active=case, alerts=[alert])

    result, run_args = detection.process(store, "AG-1147", NOW)

    assert result["action"] == "escalated" and store.reruns[0][0] == "rerun_pending"
    assert run_args["attempt"] == 1 and "rerun_pending" not in case.state


def test_rerun_refused_when_the_actor_has_another_active_case(fake_db):
    fake_db.case.status = "failed"
    fake_db.session.commit_error = IntegrityError("UPDATE cases", {}, Exception("uq_cases_account_active"))
    with pytest.raises(case_service.RerunRefused, match="another active case"):
        case_service.prepare_rerun(fake_db.session, 10)
    assert fake_db.session.rollbacks == 1 and fake_db.events == []
    fake_db.case.status = "approved"
    with pytest.raises(case_service.RerunRefused, match="only failed cases"):
        case_service.prepare_rerun(fake_db.session, 10)


def test_detection_reports_unchanged_when_the_rerun_is_refused():
    alert = make_alert(1, ["A1", "A4"], "critical")
    case = SimpleNamespace(id=10, alert_id=1, status="awaiting_review", state={})
    store = FakeStore([*s1_reads(), ev("export", records=1200, minutes_ago=1)], active=case, alerts=[alert],
                      refuse_rerun=True)
    result, run_args = detection.process(store, "AG-1147", NOW)
    assert result["action"] == "unchanged" and run_args is None


# ------------------------------------------------------------------ 3. no repeat case after a dismissal


def _dismissed(status="auto_resolved", band="medium", ended_minutes_ago=20):
    end = NOW - timedelta(minutes=ended_minutes_ago)
    case = SimpleNamespace(id=3, alert_id=2, status=status, state={})
    return case, make_alert(2, ["A1"], band, window_end=end)


def _s1b_tail():
    # The reads still arriving after S1b was auto-resolved: T2, in hours-agnostic terms just out of scope.
    return [ev("view", f"PH-c{i}", tier="T2", minutes_ago=5, device="dv-76f1", city="Pune") for i in range(70)]


def test_s1b_after_auto_resolve_opens_nothing_at_the_same_band():
    store = FakeStore(_s1b_tail(), decided=_dismissed())
    result, run_args = detection.process(store, "AG-1147", NOW)
    assert result["action"] == "none" and result["band"] == "medium"
    assert store.new_alerts == [] and store.started == [] and run_args is None
    assert store.cutoff == NOW - timedelta(minutes=20)  # step 0: only events after the window end count


def test_a_higher_band_after_a_dismissal_opens_a_case():
    reads = [ev("view", f"PH-c{i}", tier="T1", minutes_ago=5, device="dv-76f1", city="Pune") for i in range(70)]
    store = FakeStore([*reads, ev("export", records=300, minutes_ago=2, device="dv-76f1", city="Pune")],
                      decided=_dismissed())
    result, run_args = detection.process(store, "AG-1147", NOW)
    assert result["action"] == "opened" and result["band"] == "high"
    assert run_args["attempt"] == 0 and run_args["txn_ids"] == store.new_alerts[0].raw_json["txn_ids"]


def test_a_decided_case_whose_events_a_reset_deleted_does_not_block_or_cut_off_a_new_run():
    # S1b rerun 10 minutes after an auto-resolved rehearsal: the old window end is on that replay's clock, 30 minutes
    # ahead of this run's `now`, so while its events exist it both cuts off the new reads and blocks a case.
    decided = _dismissed(ended_minutes_ago=-30)
    kept = FakeStore(_s1b_tail(), decided=decided, evidence=True)
    assert detection.process(kept, "AG-1147", NOW)[0]["action"] == "none"
    assert kept.cutoff == NOW + timedelta(minutes=30)

    reset = FakeStore(_s1b_tail(), decided=decided, evidence=False)
    result, run_args = detection.process(reset, "AG-1147", NOW)
    assert result["action"] == "opened" and run_args is not None
    assert reset.cutoff is None  # no cutoff from the deleted run


@pytest.mark.parametrize("decided", [
    _dismissed(ended_minutes_ago=70),      # the hold is over
    _dismissed(status="approved"),         # approvals are not dismissals; only the cutoff applies
])
def test_dismissal_rule_applies_only_to_recent_dismissals(decided):
    result, _ = detection.process(FakeStore(_s1b_tail(), decided=decided), "AG-1147", NOW)
    assert result["action"] == "opened"


# ------------------------------------------------------------------ opening, logging, clock, labels


def test_opening_a_case_uses_the_simulated_clock_and_the_alert_mapping():
    store = FakeStore([*s1_reads(), ev("export", records=1200, minutes_ago=1)])
    result, run_args = detection.process(store, "AG-1147", NOW)
    alert, = store.new_alerts
    assert result["action"] == "opened" and result["case_id"] == store.started[0].id
    assert alert.ts == NOW  # the `now` argument, never the wall clock
    assert alert.rules == ["A1", "A3", "A4"] and alert.amount == 1840 and alert.is_laundering is True
    assert set(alert.raw_json) == {"txn_ids", "signals", "n_records", "tier", "band", "window", "actor_type"}
    assert alert.raw_json["window"]["end"] == NOW.isoformat()
    assert run_args["txn_ids"] == alert.raw_json["txn_ids"] and len(run_args["txn_ids"]) == 200


def test_low_band_is_logged_without_a_case():
    store = FakeStore([ev("login", tier="T3", records=0)])
    result, run_args = detection.process(store, "AG-1147", NOW)
    assert result["action"] == "logged" and result["band"] == "low"
    assert len(store.new_alerts) == 1 and store.started == [] and run_args is None


def test_no_signals_is_none_and_writes_nothing():
    store = FakeStore([ev("view", "PH-own", device="dv-76f1", city="Pune", minutes_ago=600)])
    result, _ = detection.process(store, "AG-1147", NOW)
    assert result == {"action": "none", "alert_id": None, "case_id": None, "risk": 0.0, "band": "low"}
    assert store.new_alerts == [] and store.commits == 0


def test_detection_never_reads_the_wall_clock():
    tree = ast.parse(Path(detection.__file__).read_text(encoding="utf-8"))
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not calls & {"now", "utcnow", "today", "time", "monotonic"}


def test_labels_and_detail_never_reach_the_detectors():
    assert "labels" not in detection.EVENT_COLUMNS and "detail" not in detection.EVENT_COLUMNS
    assert set(detection.EVENT_COLUMNS) == set(pg_rules.AccessEvent.__dataclass_fields__)
    assert set(detection.EVENT_COLUMNS) <= set(models.AccessEvent.__table__.c.keys())
