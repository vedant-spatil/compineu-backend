"""The PolicyGuard case nodes (app/agents/agents.py) and the graph (app/orchestration/graph.py).

No database and no model: the pg_data readers, the model call, Presidio and the notifier are replaced, and the session is an
in-memory fake that records audit rows, report drafts and decisions. Data comes from the golden-set scenario builders, so the
cases are the same ones the golden set uses: S1b (genuine cover), S1c (self-written ticket), S1 (AG-1147's bad night).
"""

import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from app.agents import agents
from app.db.models import Case, CaseEvent, Decision, SarDraft
from app.evaluation import golden_set as gs
from app.orchestration import graph as graph_mod
from app.orchestration.controls import CONTROL_IDS, PLAYBOOK_IDS
from app.orchestration.graph import build_graph
from app.services import llm, pg_data, pii

SAMPLE = json.loads((Path(__file__).resolve().parents[2] / "docs" / "samples" / "incident_report.sample.json")
                    .read_text(encoding="utf-8"))
BODY = "Anita covers Priya's desk during approved leave."
JUSTIFIED = {"verdict": "justified", "supporting_record_ids": [501, 502], "missing_evidence": [],
             "reasoning": "The leave and the manager's ticket cover the access."}
CLASSIFIED = {"scenario": "benign_exception", "attack_techniques": [], "cited_event_ids": [100, 101, 99999],
              "confidence": 0.8}


# ---- fakes ---------------------------------------------------------------------------------------------------------

class FakeResult:
    def __init__(self, n: int) -> None:
        self.n = n

    def scalar_one(self) -> int:
        return self.n

    def scalars(self):
        return iter(())

    def all(self) -> list:
        return []

    def first(self):
        return None


class FakeDb:
    """Stands in for the Session. One shared case, and lists of what was written."""

    def __init__(self) -> None:
        self.case = SimpleNamespace(id=1, state={}, status="open", closed_at=None)
        self.events: list[CaseEvent] = []
        self.drafts: list[SarDraft] = []
        self.decisions: list[Decision] = []

    def __enter__(self) -> "FakeDb":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, model: Any, key: Any) -> Any:
        return self.case if model is Case else None

    def add(self, obj: Any) -> None:
        {CaseEvent: self.events, SarDraft: self.drafts, Decision: self.decisions}[type(obj)].append(obj)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def execute(self, stmt: Any) -> FakeResult:
        return FakeResult(len(self.drafts))

    def payloads(self, node: str, kind: str) -> list[dict[str, Any]]:
        return [e.payload_json for e in self.events if e.node == node and e.kind == kind]


class FakeLlm:
    def __init__(self, justify: Any = JUSTIFIED, classify: Any = CLASSIFIED, report: Any = None, fail: tuple = ()) -> None:
        self.justify, self.classify, self.report, self.fail = justify, classify, report, fail
        self.calls: list[SimpleNamespace] = []

    def __call__(self, db: Any, *, model: str, system: str, user: str, schema_name: str, schema: dict,
                 max_completion_tokens: int) -> dict[str, Any]:
        self.calls.append(SimpleNamespace(model=model, schema_name=schema_name, user=user, system=system))
        if schema_name in self.fail:
            raise llm.LlmError("boom")
        if schema_name == "justify":
            return self.justify
        if schema_name == "classify":
            return self.classify
        return self.report(user) if callable(self.report) else self.report

    def names(self) -> list[str]:
        return [c.schema_name for c in self.calls]


def report_from_user(user: str) -> dict[str, Any]:
    """A REPORT answer that uses event ids from top_events, plus a playbook and a control that do not exist."""
    top = json.loads(user)["top_events"]
    return {
        "title": "Out-of-scope reads", "summary": "Summary written by the model.",
        "timeline": [{"event_id": e["event_id"], "what": "read"} for e in top[:4]] + [{"event_id": 987654321, "what": "x"}],
        "impact": {"records": 1, "tiers": {"T1": 1, "T2": 1, "T3": 1}},
        "recommended_playbooks": ["PB1", "PB5", "PB6", "PB1"], "controls_failed": ["C-PORTFOLIO", "FAKE-1", "C-EXPORT"],
        "cert_in_draft": {"summary": "DRAFT - requires DPO review. s", "incident_type": "t", "systems_affected": "s",
                          "timeline_summary": "t", "actions_taken": "a"},
        "dpdp_intimation_draft": {"nature": "DRAFT - requires DPO review. n", "extent": "e", "timing": "t",
                                  "location": "l", "likely_impact": "i"},
        "open_questions": ["Where did the file go?"],
    }


@pytest.fixture
def env(monkeypatch):
    """Patches everything outside the nodes. Returns (db, notified, stored_identities)."""
    db = FakeDb()
    notified: list[tuple] = []
    identities: list[dict[str, str]] = []
    monkeypatch.setattr(agents, "get_settings", lambda: SimpleNamespace(
        triage_model="rules", triage_threshold=0.4, llm_model_light="light-x", llm_model_heavy="heavy-x"))
    monkeypatch.setattr(agents, "notify_admins", lambda db_, kind, msg, link=None: notified.append((kind, msg, link)))
    monkeypatch.setattr(agents, "invalidate", lambda: None)
    monkeypatch.setattr(agents, "_store_identities", lambda db_, case_id, m: identities.append(dict(m)))
    monkeypatch.setattr(pii, "_presidio", lambda: SimpleNamespace(anonymize_text=lambda t: t))
    monkeypatch.setattr(graph_mod, "SessionLocal", lambda: db)
    return db, notified, identities


def install(monkeypatch, sc: gs.Scenario, *, events_error: Exception | None = None,
            portfolio_error: Exception | None = None) -> None:
    # The readable references (LV-221, TKT-4471) live in payload.ref.
    refs = {"leave": "LV-221", "ticket": "TKT-4471"}
    sc.records[:] = [dataclasses.replace(r, payload={**r.payload, "ref": refs.get(r.type, f"R-{r.id}")})
                     for r in sc.records]

    def fetch_events(db, actor, start, end, limit=20000):
        if events_error:
            raise events_error
        return [e for e in sc.events if e.actor_id == actor and start <= e.ts <= end]

    def fetch_portfolio(db, actor):
        if portfolio_error:
            raise portfolio_error
        return set(sc.portfolio)

    monkeypatch.setattr(pg_data, "fetch_events", fetch_events)
    monkeypatch.setattr(pg_data, "fetch_portfolio", fetch_portfolio)
    monkeypatch.setattr(pg_data, "fetch_agents", lambda db, ids: {i: sc.profiles[i] for i in ids if i in sc.profiles})
    monkeypatch.setattr(pg_data, "fetch_partner_key", lambda db, key: None)
    monkeypatch.setattr(pg_data, "fetch_owners", lambda db, ids: {i: sc.owners_of[i] for i in ids if i in sc.owners_of})
    monkeypatch.setattr(pg_data, "fetch_context_records", lambda db, subjects, types, **kw: list(sc.records))
    monkeypatch.setattr(pg_data, "fetch_daily_record_totals",
                        lambda db, actor, start, end, **kw: dict(sc.history.get(actor, {})))


def initial_state(sc: gs.Scenario, rules: list[str] | None = None) -> dict[str, Any]:
    return {"case_id": 1, "alert_id": 1, "account_id": sc.actor_id, "alert_ts": sc.alert_ts.isoformat(),
            "alert_rules": list(rules or sc.rules), "risk_score": sc.score, "txn_ids": sc.txn_ids or [100, 101, 102],
            "failures": [], "status": "open"}


def run_nodes(db: FakeDb, state: dict[str, Any]) -> dict[str, Any]:
    """The graph's order without LangGraph: load_context, the three branches on the same snapshot, route, then the
    auto_resolve or report_writer node. failures is appended, every other key is replaced (as the state reducers do)."""
    st = dict(state)

    def merge(update: dict[str, Any]) -> None:
        for key, value in update.items():
            st[key] = st.get("failures", []) + value if key == "failures" else value

    merge(agents.load_context(db, dict(st)))
    snapshot = dict(st)
    for node in (agents.gather_evidence, agents.justify, agents.classify):
        merge(node(db, dict(snapshot)))
    merge(agents.route_case(db, dict(st)))
    merge((agents.auto_resolve if st["route"]["action"] == "auto_resolve" else agents.report_writer)(db, dict(st)))
    return st


def build_s1b() -> gs.Scenario:
    sc = gs.build_s1b()
    sc.records[:] = [dataclasses.replace(r, payload={**r.payload, "body": BODY}) if r.type == "ticket" else r
                     for r in sc.records]
    return sc


# ---- the behaviours the brief names --------------------------------------------------------------------------------

def test_leave_plus_manager_ticket_auto_resolves(env, monkeypatch):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    fake = FakeLlm()
    monkeypatch.setattr(agents.llm, "complete_json", fake)

    st = run_nodes(db, initial_state(sc))

    assert st["justification"]["verdict"] == "justified"
    assert st["justification"]["corroboration"]["ok"] is True
    assert st["route"]["action"] == "auto_resolve" and st["route"]["band"] == "medium"
    assert st["status"] == "auto_resolved"
    assert db.case.status == "auto_resolved" and db.case.closed_at is not None
    assert fake.names() == ["justify", "classify"]  # a code-only report needs no REPORT call
    # The audit event is readable and cites the records by their references.
    (dismissed,) = db.payloads("auto_resolve", "dismissed")
    assert dismissed["verdict"] == "justified"
    assert dismissed["supporting_refs"] == ["LV-221", "TKT-4471"]
    assert "LV-221" in dismissed["summary"] and "TKT-4471" in dismissed["summary"]
    assert dismissed["reasons"] and dismissed["supporting_record_ids"] == [501, 502]
    # A report is stored too, and it says the incident was closed.
    (draft,) = db.drafts
    assert draft.body_redacted["justification"]["closes_incident"] is True
    assert draft.body_redacted["summary"].startswith("Closed automatically by code checks.")
    assert notified == [("incident_auto_resolved", "Case 1 was closed automatically after code checks.", "/cases/1")]
    # Clocks come from the simulated alert time and are stored on the case.
    assert db.case.state["clocks"]["detected_at"] == "2026-11-18T10:35:00Z"
    assert db.case.state["clocks"]["cert_in_due"] == "2026-11-18T16:35:00Z"
    assert db.case.state["clocks"]["dpdp_due"] == "2026-11-21T10:35:00Z"
    # The ticket text reaches the model only inside <evidence>, and never the audit trail.
    justify_user = next(c.user for c in fake.calls if c.schema_name == "justify")
    assert BODY in justify_user and justify_user.index(BODY) > justify_user.index("<evidence>")
    assert BODY not in " ".join(json.dumps(e.payload_json) for e in db.events)


def test_self_written_ticket_is_promoted_to_a_human(env, monkeypatch):
    db, notified, _ = env
    sc = gs.build_s1c()
    install(monkeypatch, sc)
    fake = FakeLlm(justify={**JUSTIFIED, "supporting_record_ids": [601]}, report=report_from_user)
    monkeypatch.setattr(agents.llm, "complete_json", fake)

    st = run_nodes(db, initial_state(sc))

    assert st["justification"]["llm_verdict"] == "justified"  # the model said justified ...
    assert st["justification"]["verdict"] == "inconclusive"  # ... and code overrode it
    assert "record_authored_by_actor_or_owner" in st["justification"]["corroboration"]["failed_checks"]
    assert st["route"]["action"] == "investigate" and st["route"]["band"] == "medium"
    assert "corroboration_not_ok" in st["route"]["blockers"]
    assert fake.names() == ["justify", "classify", "incident_report"]
    assert st.get("status") != "auto_resolved" and db.case.status == "open"
    assert not notified and not db.payloads("auto_resolve", "dismissed")
    report = st["incident_report"]
    assert report["justification"]["closes_incident"] is False
    assert report["justification"]["corroboration"]["failed_checks"]  # the missing proof is listed
    # Controls broken are decided in code from the signals: S1c fires A1 only (no export), so only C-PORTFOLIO.
    assert report["recommended_playbooks"] == ["PB1", "PB6"] and report["controls_failed"] == ["C-PORTFOLIO"]
    assert len(db.drafts) == 1


@pytest.mark.parametrize("extra,blocker", [("I1_inactive_identity", "hard_signal:I1"),
                                           ("A3_bulk_export", "never_auto_signal:A3")])
def test_hard_and_never_auto_signals_are_never_auto_resolved(env, monkeypatch, extra, blocker):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(report=report_from_user))

    st = run_nodes(db, initial_state(sc, ["A1_out_of_portfolio", extra]))

    assert st["justification"]["verdict"] == "justified"  # the proof exists ...
    assert st["route"]["action"] == "investigate" and blocker in st["route"]["blockers"]  # ... a human still decides
    assert db.case.status == "open" and not notified and st["incident_report"] is not None


def test_a_data_error_becomes_a_failure_and_blocks_auto_resolve(env, monkeypatch):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc, events_error=pg_data.PgDataError("access_events", "OperationalError"))
    fake = FakeLlm(report=report_from_user)
    monkeypatch.setattr(agents.llm, "complete_json", fake)

    st = run_nodes(db, initial_state(sc))  # does not raise

    assert "load_context: access_events unavailable" in st["failures"]
    assert "evidence: access_events unavailable" in st["failures"]
    assert st["route"]["action"] == "investigate"
    assert {"failure:load_context", "failure:evidence"} <= set(st["route"]["blockers"])
    assert db.payloads("load_context", "error") and db.case.status == "open" and not notified
    assert "justify" not in fake.names()  # no context, so the model is not asked to justify anything
    report = st["incident_report"]  # a code-only report still reaches the reviewer, and says what is missing
    assert any("could not be loaded" in q for q in report["open_questions"])
    assert report["justification"]["corroboration"]["failed_checks"] == ["context_unavailable"]


def test_a_node_that_hits_an_unexpected_error_does_not_raise(env, monkeypatch):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc, portfolio_error=RuntimeError("boom"))
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(report=report_from_user))

    st = run_nodes(db, initial_state(sc))

    assert "load_context: RuntimeError" in st["failures"] and "evidence: RuntimeError" in st["failures"]
    assert st["route"]["action"] == "investigate" and not notified
    assert db.payloads("load_context", "error") and db.payloads("evidence", "error")


def test_a_failed_justification_call_blocks_auto_resolve(env, monkeypatch):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(fail=("justify",), report=report_from_user))

    st = run_nodes(db, initial_state(sc))

    assert "justification: llm failed" in st["failures"]
    assert st["justification"]["verdict"] == "inconclusive" and "llm_unavailable" in st["justification"]["gate_reasons"]
    assert st["justification"]["corroboration"]["ok"] is True  # the proof exists, but the failure still blocks
    assert "failure:justification" in st["route"]["blockers"] and st["route"]["action"] == "investigate"
    assert db.case.status == "open" and not notified


def test_a_cited_record_that_was_not_fetched_is_overridden_to_inconclusive(env, monkeypatch):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(
        justify={**JUSTIFIED, "supporting_record_ids": [501, 502, 999999]}, report=report_from_user))

    st = run_nodes(db, initial_state(sc))

    just = st["justification"]
    assert just["llm_verdict"] == "justified" and just["verdict"] == "inconclusive"
    assert "cited_unknown_record" in just["gate_reasons"] and just["supporting_record_ids"] == [501, 502]
    assert st["route"]["action"] == "investigate" and db.case.status == "open" and not notified
    (done,) = db.payloads("justification", "done")
    assert done["verdict"] == "inconclusive" and done["gate_reasons"] == just["gate_reasons"]


# ---- names, ids and the report shape -------------------------------------------------------------------------------

def test_names_never_reach_the_model_or_the_stored_report(env, monkeypatch):
    db, _, identities = env
    sc = build_s1b()
    owner = dataclasses.replace(sc.profiles["AG-2201"], name="Priya Joshi")
    sc.profiles["AG-2201"] = owner
    sc.records[:] = [dataclasses.replace(r, payload={**r.payload, "body": "Anita covers Priya Joshi's desk."})
                     if r.type == "ticket" else r for r in sc.records]
    install(monkeypatch, sc)
    monkeypatch.setattr(agents, "_policyholder_identities", lambda db_, ev: {"PH_001": "Jane Roe"})

    def report(user: str) -> dict[str, Any]:
        out = report_from_user(user)
        out["summary"] = "Jane Roe's file and Priya Joshi's desk were involved."
        return out

    fake = FakeLlm(report=report)
    monkeypatch.setattr(agents.llm, "complete_json", fake)
    st = run_nodes(db, initial_state(sc, ["A1_out_of_portfolio", "A3_bulk_export"]))

    justify_user = next(c.user for c in fake.calls if c.schema_name == "justify")
    assert "Priya Joshi" not in justify_user and "[AG-2201]" in justify_user
    assert "Priya Joshi" not in json.dumps(st["context"]) and "Priya Joshi" not in json.dumps(st["justification"])
    stored = json.dumps(db.drafts[0].body_redacted)
    assert "Jane Roe" not in stored and "Priya Joshi" not in stored
    assert identities == [{"PH_001": "Jane Roe"}]  # the encrypted token -> name map is stored for the reveal button
    assert "Jane" not in " ".join(json.dumps(e.payload_json) for e in db.events)


def _keys_of(obj: dict[str, Any]) -> dict[str, Any]:
    return {"top": set(obj), "impact": set(obj["impact"]), "justification": set(obj["justification"]),
            "corroboration": set(obj["justification"]["corroboration"]), "clocks": set(obj["clocks"]),
            "cert_in": set(obj["cert_in_draft"]), "dpdp": set(obj["dpdp_intimation_draft"]),
            "tiers": set(obj["impact"]["tiers"]), "timeline": {frozenset(t) for t in obj["timeline"]}}


def test_the_report_has_exactly_the_keys_of_the_sample(env, monkeypatch):
    db, _, _ = env
    sc = gs.build_s1()
    install(monkeypatch, sc)
    fake = FakeLlm(classify={"scenario": "malicious_insider", "attack_techniques": ["T1078", "T1213", "bogus"],
                             "cited_event_ids": [2000, 5000, 424242], "confidence": 0.9}, report=report_from_user)
    monkeypatch.setattr(agents.llm, "complete_json", fake)
    st = run_nodes(db, initial_state(sc))

    report = json.loads(json.dumps(st["incident_report"]))  # JSON-safe
    assert report == json.loads(json.dumps(db.drafts[0].body_redacted))
    got, want = _keys_of(report), _keys_of(SAMPLE)
    assert got == {**want, "timeline": {frozenset({"event_id", "ts", "what"})}}
    assert want["timeline"] == {frozenset({"event_id", "ts", "what"})}
    # Types the frontend relies on (src/api/report.ts).
    assert report["actor"] == "AG-1147" and "exported_rows" not in report["impact"] and "agent_id" not in report
    assert report["risk_score"] == 89 and isinstance(report["risk_score"], int) and report["severity"] == "Critical"
    assert report["scenario"] == "malicious_insider" and report["attack_techniques"] == ["T1078", "T1213"]
    assert report["detected_at"] == "2026-11-19T00:55:00Z" == report["clocks"]["detected_at"]
    assert report["clocks"]["cert_in_due"] == "2026-11-19T06:55:00Z"
    assert report["clocks"]["dpdp_due"] == "2026-11-22T00:55:00Z"
    assert all(isinstance(i, int) for i in report["cited_event_ids"]) and 424242 not in report["cited_event_ids"]
    assert report["cited_event_ids"][:2] == [2000, 5000]
    assert report["impact"] == {"records": 1840, "rows_exported": 1200, "policyholders": 1840,
                                "outside_portfolio_records": 1840, "tiers": {"T1": 920, "T2": 460, "T3": 460}}
    assert report["justification"]["closes_incident"] is False and isinstance(report["justification"]["closes_incident"], bool)
    assert set(report["recommended_playbooks"]) <= set(PLAYBOOK_IDS) and "PB5" not in report["recommended_playbooks"]
    assert set(report["controls_failed"]) <= set(CONTROL_IDS)
    assert all(e["event_id"] != 987654321 for e in report["timeline"])
    assert st["route"]["band"] == "incident" and db.case.status == "open"
    # The sample itself obeys the same contract.
    assert SAMPLE["actor"] == "AG-1147" and "rows_exported" in SAMPLE["impact"]
    assert set(SAMPLE["recommended_playbooks"]) <= set(PLAYBOOK_IDS) and set(SAMPLE["controls_failed"]) <= set(CONTROL_IDS)


def test_a_report_answer_with_json_strings_for_the_nested_drafts_is_decoded(env, monkeypatch):
    """Sonnet returned cert_in_draft and dpdp_intimation_draft as JSON strings in the real run (case 10)."""
    db, _, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)

    def report(user: str) -> dict[str, Any]:
        out = report_from_user(user)
        out["cert_in_draft"] = json.dumps(out["cert_in_draft"])
        out["dpdp_intimation_draft"] = "plain text that is not JSON"
        out["open_questions"] = "not a list"
        out["timeline"] = "not a list either"
        return out

    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(report=report))
    st = run_nodes(db, initial_state(sc, ["A1_out_of_portfolio", "A3_bulk_export"]))

    rep = st["incident_report"]
    assert rep["cert_in_draft"]["incident_type"] == "t" and rep["cert_in_draft"]["summary"].startswith("DRAFT")
    assert rep["dpdp_intimation_draft"]["nature"] == "plain text that is not JSON"
    assert rep["open_questions"] == [] and rep["timeline"]  # the timeline falls back to the code-built one
    assert "report_writer: narrative discarded" not in st["failures"]


def test_a_report_is_still_stored_when_the_model_answer_breaks_assembly(env, monkeypatch):
    db, _, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(report=report_from_user))
    real = agents.assembly.assemble_report_ex

    def flaky(llm_out, **kw):
        if llm_out is not None:
            raise TypeError("unexpected shape")
        return real(llm_out, **kw)

    monkeypatch.setattr(agents.assembly, "assemble_report_ex", flaky)
    st = run_nodes(db, initial_state(sc, ["A1_out_of_portfolio", "A3_bulk_export"]))

    assert "report_writer: narrative discarded" in st["failures"] and len(db.drafts) == 1
    assert st["incident_report"]["open_questions"]  # says the narrative was assembled by code only
    assert db.payloads("report_writer", "error")[0]["stage"] == "assemble"


def test_a_code_only_report_has_the_same_keys(env, monkeypatch):
    db, _, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(fail=("incident_report",), report=report_from_user))

    st = run_nodes(db, initial_state(sc, ["A1_out_of_portfolio", "A3_bulk_export"]))

    assert "report_writer: llm failed" in st["failures"]
    assert _keys_of(st["incident_report"]) == {**_keys_of(SAMPLE), "timeline": {frozenset({"event_id", "ts", "what"})}}
    assert st["incident_report"]["timeline"] and any("narrative" in q.lower() for q in st["incident_report"]["open_questions"])


# ---- the compiled graph (in-memory checkpointer) -------------------------------------------------------------------

def _config() -> dict[str, Any]:
    return {"configurable": {"thread_id": "1"}, "recursion_limit": 20}


def test_graph_auto_resolves_the_genuine_cover(env, monkeypatch):
    db, notified, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm())
    graph = build_graph(MemorySaver())

    final = graph.invoke(initial_state(sc), _config())

    assert final["status"] == "auto_resolved" and db.case.status == "auto_resolved"
    assert final["route"]["action"] == "auto_resolve" and not graph.get_state(_config()).next
    assert db.payloads("auto_resolve", "dismissed")[0]["supporting_refs"] == ["LV-221", "TKT-4471"]
    assert [e.node for e in db.events if e.kind != "error"][:2] == ["triage", "load_context"]
    assert len(notified) == 1


def test_graph_low_risk_alert_is_closed_at_triage(env, monkeypatch):
    db, _, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    fake = FakeLlm()
    monkeypatch.setattr(agents.llm, "complete_json", fake)
    state = initial_state(sc)
    state["risk_score"] = 0.2

    final = build_graph(MemorySaver()).invoke(state, _config())

    assert final["status"] == "closed_low_risk" and not fake.calls and db.case.status == "closed"


def test_graph_promotes_the_forged_ticket_then_stores_playbooks_on_approval(env, monkeypatch):
    db, _, _ = env
    sc = gs.build_s1c()
    install(monkeypatch, sc)
    monkeypatch.setattr(agents.llm, "complete_json", FakeLlm(justify={**JUSTIFIED, "supporting_record_ids": [601]},
                                                              report=report_from_user))
    monkeypatch.setitem(__import__("sys").modules, "app.services.playbooks", None)  # the executor is not on main yet
    graph = build_graph(MemorySaver())

    first = graph.invoke(initial_state(sc), _config())

    review = first["__interrupt__"][0].value
    assert set(review) == {"case_id", "report", "route", "failures"}
    assert review["route"]["action"] == "investigate" and review["report"]["justification"]["closes_incident"] is False
    assert db.case.status == "awaiting_review" and graph.get_state(_config()).next == ("await_human",)

    decision = {"action": "approve", "reason": "x" * 25, "typologies": [], "actor_user_id": 7,
                "playbooks": ["PB1", "PB5", "PB1", "PB7"]}
    final = graph.invoke(Command(resume=decision), _config())

    assert final["status"] == "approved" and db.case.status == "approved"
    (stored,) = db.decisions
    assert stored.playbooks == ["PB1", "PB7"] and stored.action == "approve" and stored.actor_user_id == 7
    assert db.payloads("finalize", "playbooks_skipped") == [{"requested": ["PB1", "PB7"]}]


def test_finalize_calls_run_playbooks_when_the_module_exists(env, monkeypatch):
    db, _, _ = env
    calls: list[tuple] = []
    fake_module = SimpleNamespace(run_playbooks=lambda *a: calls.append(a))
    monkeypatch.setitem(__import__("sys").modules, "app.services.playbooks", fake_module)

    out = graph_mod._finalize({"case_id": 1, "decision": {"action": "approve", "reason": "r" * 25, "actor_user_id": 7,
                                                           "playbooks": ["PB2", "PB6"]}})
    close = graph_mod._finalize({"case_id": 1, "decision": {"action": "close", "reason": "r" * 25, "actor_user_id": 7,
                                                             "playbooks": ["PB2"]}})

    assert out == {"status": "approved"} and close == {"status": "closed"}
    assert calls == [(db, 1, ["PB2", "PB6"], 7, "r" * 25)]  # only the approval ran playbooks
    assert [d.playbooks for d in db.decisions] == [["PB2", "PB6"], []]


# ---- scenario floor (the label on screen is derived in code where the signals and checks decide it) -----------------

def test_a_wrong_model_label_is_floored_and_the_classify_audit_event_records_it(env, monkeypatch):
    db, _, _ = env
    sc = gs.build_s1c()
    install(monkeypatch, sc)
    fake = FakeLlm(classify={**CLASSIFIED, "scenario": "benign_exception"}, report=report_from_user)
    monkeypatch.setattr(agents.llm, "complete_json", fake)

    st = run_nodes(db, initial_state(sc))

    (done,) = db.payloads("classify", "done")
    assert done["scenario"] == "malicious_insider" and done["scenario_source"] == "code_floor"
    assert done["model_scenario"] == "benign_exception" and "record_authored_by_actor_or_owner" in done["floor_reason"]
    assert st["classification"]["scenario_source"] == "code_floor"
    report = st["incident_report"]
    assert report["scenario"] == "malicious_insider" and "scenario_source" not in report  # the frontend key is unchanged


def test_the_justified_verdict_floors_the_label_at_route_time(env, monkeypatch):
    db, _, _ = env
    sc = build_s1b()
    install(monkeypatch, sc)
    fake = FakeLlm(classify={**CLASSIFIED, "scenario": "negligent"})
    monkeypatch.setattr(agents.llm, "complete_json", fake)

    st = run_nodes(db, initial_state(sc))

    (done,) = db.payloads("classify", "done")
    assert done["scenario"] == "negligent" and done["scenario_source"] == "model"  # the verdict is not known to this branch
    (route,) = db.payloads("route", "decision")
    assert route["scenario_floor"]["scenario"] == "benign_exception" and route["scenario_floor"]["scenario_source"] == "code_floor"
    assert route["scenario_floor"]["model_scenario"] == "negligent"
    assert st["classification"]["scenario"] == "benign_exception"
    assert st["route"]["action"] == "auto_resolve" and st["incident_report"]["scenario"] == "benign_exception"


def test_a_model_label_that_the_floor_agrees_with_is_left_as_the_models(env, monkeypatch):
    db, _, _ = env
    sc = gs.build_s1()
    install(monkeypatch, sc)
    fake = FakeLlm(classify={**CLASSIFIED, "scenario": "malicious_insider"}, report=report_from_user)
    monkeypatch.setattr(agents.llm, "complete_json", fake)

    st = run_nodes(db, initial_state(sc))

    (done,) = db.payloads("classify", "done")
    assert done["scenario"] == "malicious_insider" and done["scenario_source"] == "model" and done["floor_reason"] == ""
    assert "scenario_floor" not in db.payloads("route", "decision")[0]
    assert st["incident_report"]["scenario"] == "malicious_insider"
