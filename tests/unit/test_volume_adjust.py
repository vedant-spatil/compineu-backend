from app.evaluation.volume_adjust import trim_events, views_to_keep


def _ev(action: str, i: int, ph: str | None = None) -> dict:
    return {"event_id": f"e{i}", "action": action, "policyholder_id": ph}


def test_views_to_keep_is_two_under_the_floor_of_p95_and_never_below_twelve():
    assert views_to_keep(136.9) == 134
    assert views_to_keep(25.8) == 23
    assert views_to_keep(13.0) == 12
    assert views_to_keep(0.0) == 12
    assert views_to_keep(None) is None


def test_trim_keeps_login_search_and_export_and_the_first_views_in_order():
    events = [_ev("login", 0), _ev("search", 1), *[_ev("view", 2 + i, f"PH-{i}") for i in range(10)], _ev("export", 12)]
    out = trim_events(events, 4)
    assert [e["event_id"] for e in out] == ["e0", "e1", "e2", "e3", "e4", "e5", "e12"]
    assert [e["action"] for e in out].count("view") == 4
    assert trim_events(events, 99) == events
