"""The owner's own p95 is only a proof when it rests on enough days: MIN_BASELINE_DAYS = 3 (S1b's owner has 22 days in the full
world; the small fixture's 2 days are not enough, on purpose)."""

import pytest

from app.evaluation import golden_set as gs
from app.orchestration.corroboration import MIN_BASELINE_DAYS


def _s1b_with_history(days: list[int]):
    sc = gs.build_s1b()
    sc.history["AG-2201"] = gs._history(days)
    return gs.run_chain(sc)


def test_the_limit_is_three_days():
    assert MIN_BASELINE_DAYS == 3


@pytest.mark.parametrize("days", [[], [60], [60, 62]])
def test_fewer_than_three_history_days_fail_the_baseline_check(days):
    res = _s1b_with_history(days)
    assert "owner_baseline_missing" in res["corroboration"].failed_checks
    assert res["route"].action == "investigate"


def test_three_history_days_are_enough():
    res = _s1b_with_history([60, 62, 61])
    assert res["corroboration"].ok and res["route"].action == "auto_resolve"
