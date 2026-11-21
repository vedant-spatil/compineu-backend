"""Playbooks (T9) with the database, the evidence helper and notifications mocked."""

import inspect
from types import SimpleNamespace

import pytest

from app.db import models
from app.services import evidence, playbooks

REASON = "Out-of-portfolio bulk export at night from a new device."


class FakeDb:
    def __init__(self, subject="AG-1147", agent=True, key=False):
        self.case = SimpleNamespace(id=7, account_id=subject, alert_id=3, status="approved", risk_score=0.887)
        self.agent = SimpleNamespace(agent_id=subject, credential_enabled=True) if agent else None
        self.key = SimpleNamespace(key_id=subject, enabled=True) if key else None
        self.user = SimpleNamespace(id=2, email="admin@pg.local")
        self.commits = self.rollbacks = 0

    def get(self, model, key):
        return {models.Case: self.case, models.Agent: self.agent, models.PartnerKey: self.key,
                models.User: self.user}.get(model)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def audit(monkeypatch):
    events, notes = [], []
    monkeypatch.setattr(playbooks, "write_event", lambda db, case_id, node, kind, payload: events.append(
        (case_id, node, kind, payload)))
    monkeypatch.setattr(playbooks, "notify_admins", lambda db, kind, message, link=None: notes.append(
        (kind, message, link)))
    monkeypatch.setattr(playbooks, "invalidate", lambda: None)
    monkeypatch.setattr(playbooks, "evidence_bundle", lambda db, case_id: {"case": {"id": case_id},
                                                                           "access_events": [{"id": 192717}]})
    return SimpleNamespace(events=events, notes=notes)


def test_signature_matches_bhavyas_finalize_call():
    assert list(inspect.signature(playbooks.run_playbooks).parameters) == [
        "db", "case_id", "playbooks", "actor_user_id", "reason"]


def test_pb1_disables_the_agents_credential(audit):
    db = FakeDb()
    results = playbooks.run_playbooks(db, 7, ["PB1"], 2, REASON)
    assert db.agent.credential_enabled is False and db.commits == 1
    assert results == [{"playbook": "PB1", "result": "done", "subject": "AG-1147", "credential_enabled": False,
                        "already_disabled": False}]
    (case_id, node, kind, payload), = audit.events
    assert (case_id, node, kind) == (7, "playbook", "PB1")
    assert payload["result"] == "done" and payload["approver"] == 2 and payload["reason"] == REASON


def test_pb1_is_not_applicable_to_a_partner_key_and_pb2_disables_it(audit):
    db = FakeDb(subject="PK-CARELINK", agent=False, key=True)
    results = playbooks.run_playbooks(db, 7, ["PB1", "PB2"], 2, REASON)
    assert [r["result"] for r in results] == ["not_applicable", "done"]
    assert db.key.enabled is False
    assert [e[2] for e in audit.events] == ["PB1", "PB2"]


def test_pb6_sends_the_bundle_to_preserve_evidence(audit, monkeypatch):
    calls = []

    def fake_preserve(db, case_id, bundle, *, approved_by, reason, client=None):
        calls.append((case_id, bundle, approved_by, reason))
        return {"key": "incidents/7/20261120T110000Z-abc.json", "version_id": "v1", "retain_until": "2026-11-21"}

    monkeypatch.setattr(evidence, "preserve_evidence", fake_preserve)
    results = playbooks.run_playbooks(FakeDb(), 7, ["PB6"], 2, REASON)
    (case_id, bundle, approved_by, reason), = calls
    assert case_id == 7 and bundle["access_events"] == [{"id": 192717}]
    assert approved_by == "admin@pg.local" and reason == REASON
    assert results[0]["result"] == "done" and results[0]["key"].startswith("incidents/7/")


def test_pb6_without_a_bucket_is_recorded_as_an_error_and_the_rest_still_run(audit, monkeypatch):
    def no_bucket(*args, **kwargs):
        raise evidence.EvidenceError("EVIDENCE_BUCKET is not set; PB6 cannot run")

    monkeypatch.setattr(evidence, "preserve_evidence", no_bucket)
    db = FakeDb()
    results = playbooks.run_playbooks(db, 7, ["PB1", "PB6", "PB7"], 2, REASON)  # must not raise
    assert [(r["playbook"], r["result"]) for r in results] == [("PB1", "done"), ("PB6", "error"), ("PB7", "done")]
    assert "EVIDENCE_BUCKET" in results[1]["error"] and db.rollbacks == 1
    assert audit.events[1][3]["result"] == "error"
    message = audit.notes[0][1]
    assert "PB1" in message and "PB6" not in message  # the notification says only what was done


def test_pb7_notifies_the_admins_with_a_link(audit):
    playbooks.run_playbooks(FakeDb(), 7, ["PB7"], 2, REASON)
    (kind, _message, link), = audit.notes
    assert kind == "incident_actioned" and link == "/cases/7"


def test_playbooks_run_in_a_fixed_order_once_each(audit):
    results = playbooks.run_playbooks(FakeDb(), 7, ["PB7", "PB1", "PB7"], 2, REASON)
    assert [r["playbook"] for r in results] == ["PB1", "PB7"]


def test_an_unknown_or_crashing_playbook_is_recorded_never_raised(audit, monkeypatch):
    def boom(db, case_id, **kwargs):
        raise RuntimeError("agents table locked")

    monkeypatch.setitem(playbooks.PLAYBOOKS, "PB1", boom)
    results = playbooks.run_playbooks(FakeDb(), 7, ["PB1", "PB5"], 2, REASON)
    assert [(r["playbook"], r["result"]) for r in results] == [("PB1", "error"), ("PB5", "error")]
    assert "agents table locked" in results[0]["error"] and "unknown playbook" in results[1]["error"]
    assert [e[2] for e in audit.events] == ["PB1", "PB5"]


def test_a_failing_audit_write_does_not_raise(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("database gone")

    monkeypatch.setattr(playbooks, "write_event", broken)
    monkeypatch.setattr(playbooks, "invalidate", lambda: None)
    assert playbooks.run_playbooks(FakeDb(), 7, ["PB1"], 2, REASON)[0]["result"] == "done"


def test_the_evidence_bundle_leaves_out_ground_truth_labels():
    assert "labels" not in playbooks.EVIDENCE_EVENT_COLUMNS
    assert set(playbooks.EVIDENCE_EVENT_COLUMNS) <= set(models.AccessEvent.__table__.c.keys())
