from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.api.routers import cases as cases_router
from app.api.routers.cases import DecisionIn

REASON = "x" * 25


def test_reason_minimum_length():
    with pytest.raises(ValidationError):
        DecisionIn(action="close", reason="too short", reviewed=True)


def test_action_enum_only_approve_or_close():
    with pytest.raises(ValidationError):
        DecisionIn(action="escalate", reason=REASON, reviewed=True)


def test_valid_decision():
    d = DecisionIn(action="approve", reason=REASON, reviewed=True, typologies=["structuring"])
    assert d.action == "approve"
    assert d.playbooks == []  # the default


def test_approve_accepts_the_built_playbooks():
    d = DecisionIn(action="approve", reason=REASON, reviewed=True, playbooks=["PB1", "PB6", "PB7"])
    assert d.playbooks == ["PB1", "PB6", "PB7"]


@pytest.mark.parametrize("unknown", ["PB5", "PB3", "pb1", ""])
def test_unknown_playbooks_are_refused(unknown):
    with pytest.raises(ValidationError):
        DecisionIn(action="approve", reason=REASON, reviewed=True, playbooks=[unknown])


def test_close_with_playbooks_is_refused_and_close_without_is_fine():
    with pytest.raises(ValidationError, match="only on approve"):
        DecisionIn(action="close", reason=REASON, reviewed=True, playbooks=["PB7"])
    assert DecisionIn(action="close", reason=REASON, reviewed=True, playbooks=[]).playbooks == []


def test_duplicate_playbooks_run_once_in_order():
    d = DecisionIn(action="approve", reason=REASON, reviewed=True, playbooks=["PB6", "PB1", "PB6"])
    assert d.playbooks == ["PB6", "PB1"]


def test_extra_fields_are_still_forbidden():
    with pytest.raises(ValidationError):
        DecisionIn(action="approve", reason=REASON, reviewed=True, playbooks=[], urgent=True)


def test_decide_passes_playbooks_to_resume_case(monkeypatch):
    case = SimpleNamespace(id=7, status="awaiting_review")
    resumed = []
    monkeypatch.setattr(cases_router, "get_visible_case", lambda db, user, case_id: case)
    monkeypatch.setattr(cases_router.case_service, "resume_case", lambda case_id, d: resumed.append((case_id, d)))
    monkeypatch.setattr(cases_router, "_case_out", lambda c: c)
    body = DecisionIn(action="approve", reason=REASON, reviewed=True, playbooks=["PB1", "PB6"])
    db = SimpleNamespace(refresh=lambda obj: None)
    user = SimpleNamespace(id=3, role="admin")

    cases_router.decide(7, body, user, db)

    (case_id, decision), = resumed
    assert case_id == 7
    assert decision == {"action": "approve", "reason": REASON, "typologies": [], "actor_user_id": 3,
                        "playbooks": ["PB1", "PB6"]}
