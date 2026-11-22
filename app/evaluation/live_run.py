"""Live golden set: the real production path with the real models, on the FULL world.

    python -m app.evaluation.golden_set --live [--data data/policyguard] [--label as_generated] [--fresh-cache] [--cases EG1,EF2]

Needs the full world in the database (python -m app.ingest.pg_load data/policyguard --reset), LLM_PROVIDER=groq and a
GROQ_API_KEY. For each case: the scenario's recorded events are inserted (if not there yet), then
detection.process_actor(actor, end + 1 s) opens the case and the real compiled graph runs it (triage, load_context,
evidence | justification | classify, route, then auto_resolve or report_writer). Nothing is simulated except the clock.

Model use: JUSTIFY and CLASSIFY (light model) run for every case. REPORT (heavy model) runs only for REAL_REPORT_CASES; for the
other promoted cases the REPORT call is not made and the report is built by code alone (cost cap), which changes no route.

Every provider reply is captured at the HTTP layer (services.llm._post), so the schema check sees exactly what the model
returned, before any decoding or repair by our code. Ground truth (manifest is_attack, expected_route) is read here and only
here, to score the run. Detection and the prompts never see it.

Each run is stored as one labelled section of docs/eval/golden_set_live_results.json; golden_set_numbers.md shows every section.
"""

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from sqlalchemy import text

from app.evaluation.report_contract import STORED_REPORT_SCHEMA, validate
from app.orchestration.prompts import CLASSIFY_SCHEMA, JUSTIFY_SCHEMA, REPORT_SCHEMA, SCENARIOS, VERDICTS

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_JSON = REPO_ROOT / "docs" / "eval" / "golden_set_live_results.json"  # equals golden_set.LIVE_OUT
OUT_MD = REPO_ROOT / "docs" / "eval" / "golden_set_numbers.md"

GENUINE = [f"EG{i}" for i in range(1, 9)]
FORGED = [f"EF{i}" for i in range(1, 6)]
CONTEXT = ["S1b", "S1c", "S1d", "S1", "S5"]
ALL_CASES = [*GENUINE, *FORGED, *CONTEXT]
REAL_REPORT_CASES = frozenset({"S1", "S5", "EF1", "EF4"})  # heavy model only here; EF4 is a forged ticket on a real leave
SCHEMAS = {"justify": JUSTIFY_SCHEMA, "classify": CLASSIFY_SCHEMA, "incident_report": REPORT_SCHEMA}
SHORT = {"justify": "JUSTIFY", "classify": "CLASSIFY", "incident_report": "REPORT"}
SECTION_TITLES = {
    "as_generated": "AS GENERATED (data/policyguard, exactly what pg_generate wrote)",
    "volume_adjusted_local_copy": "VOLUME-ADJUSTED LOCAL COPY (EG/EF cover views trimmed to the owner's p95; local only, not the "
                                  "generator's output)",
}
CASE_TIMEOUT_S = 420
VOLUME_CODE = "volume_exceeds_owner_p95"


class Recorder:
    """Wraps llm._post (every HTTP exchange) and llm.complete_json (cache hits, REPORT cost cap)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.cache_hits: list[dict[str, Any]] = []
        self.skipped_reports: list[str] = []
        self.current: str | None = None

    def install(self) -> None:
        from app.services import llm

        self._llm = llm
        self._post, self._complete = llm._post, llm.complete_json
        llm._post, llm.complete_json = self.post, self.complete

    def uninstall(self) -> None:
        self._llm._post, self._llm.complete_json = self._post, self._complete

    def post(self, req: Any) -> Any:
        t0 = time.monotonic()
        resp = self._post(req)
        tool = req.body["toolConfig"]["tools"][0]["toolSpec"]["name"]
        rec: dict[str, Any] = {
            "case": self.current, "schema": tool, "model": unquote(req.url.split("/model/")[1].split("/")[0]),
            "http_status": resp.status_code, "seconds": round(time.monotonic() - t0, 2), "ok": bool(resp.is_success)}
        if resp.is_success:
            payload = resp.json()
            usage = payload.get("usage") or {}
            rec.update(input_tokens=usage.get("inputTokens"), output_tokens=usage.get("outputTokens"),
                       stop_reason=payload.get("stopReason"))
            raw = next((b["toolUse"]["input"] for b in payload.get("output", {}).get("message", {}).get("content", [])
                        if isinstance(b, dict) and (b.get("toolUse") or {}).get("name") == tool), None)
            errors = validate(raw, SCHEMAS[tool]) if isinstance(raw, dict) else ["no tool input object in the reply"]
            rec.update(valid_as_returned=not errors, schema_errors=errors[:8])
            if errors:  # keep the offending reply (agent ids, tokens and counts only: names never reach the model)
                rec["raw_reply"] = raw
        self.calls.append(rec)
        return resp

    def complete(self, db: Any, **kw: Any) -> dict[str, Any]:
        if kw["schema_name"] == "incident_report" and self.current not in REAL_REPORT_CASES:
            self.skipped_reports.append(str(self.current))
            raise self._llm.LlmError("golden set: REPORT model call not made for this case (cost cap)")
        before = len(self.calls)
        out = self._complete(db, **kw)
        if len(self.calls) == before:
            self.cache_hits.append({"case": self.current, "schema": kw["schema_name"]})
        return out


def _wait_for_case_threads(limit: float = CASE_TIMEOUT_S) -> bool:
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        live = [t for t in threading.enumerate() if t.name.startswith("case-") and t.is_alive()]
        if not live:
            return True
        for t in live:
            t.join(timeout=2)
    return False


def _q(sql: str, **params: Any) -> list[dict[str, Any]]:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        return [dict(r._mapping) for r in db.execute(text(sql), params)]


def _ensure_events(src: Path, sids: list[str], replace: bool) -> dict[str, str]:
    """Insert each scenario's recorded events (pg_load's COPY and row format) unless they are already there. With replace,
    the scenario's existing events are deleted first (used for the volume-adjusted copy)."""
    from app.db.session import engine
    from app.ingest import pg_load

    like = {s: f"ev-{s.lower()}-%" for s in sids}
    with engine.begin() as c:
        if replace:
            for s in sids:
                c.execute(text("DELETE FROM access_events WHERE detail->>'event_ref' LIKE :p"), {"p": like[s]})
        present = {s: c.execute(text("SELECT count(*) FROM access_events WHERE detail->>'event_ref' LIKE :p"),
                                {"p": like[s]}).scalar_one() for s in sids}
    todo = [s for s in sids if not present[s]]
    inserted: dict[str, int] = {}
    if todo:
        raw = engine.raw_connection()
        try:
            with raw.driver_connection.cursor() as cur:
                for s in todo:
                    inserted[s] = pg_load._copy(cur, "access_events", pg_load.EVENT_COLS,
                                                (pg_load.event_row(e) for e in pg_load._lines(src / "scenarios" / f"{s}.jsonl")))
            raw.driver_connection.commit()
        except Exception:
            raw.driver_connection.rollback()
            raise
        finally:
            raw.close()
    return {s: (f"inserted {inserted[s]}" if s in inserted else f"already there ({present[s]})") for s in sids}


def _preflight(manifest: dict[str, Any], cases: list[str]) -> dict[str, dict[str, Any]]:
    """What detection will compute for each case (pg_rules.detect on the loaded events), without writing anything."""
    from app.db.session import SessionLocal
    from app.ingest import pg_rules
    from app.services import detection

    out: dict[str, dict[str, Any]] = {}
    with SessionLocal() as db:
        store = detection.Store(db)
        for sid in cases:
            m = manifest[sid]
            now = datetime.fromisoformat(m["end"]) + timedelta(seconds=1)
            inputs = store.inputs(m["actor"], None, now)
            if inputs is None:
                out[sid] = {"error": "actor not found"}
                continue
            det = pg_rules.detect(m["actor"], inputs.actor_type, inputs.events, now, agent=inputs.agent, scope=inputs.scope,
                                  partner=inputs.partner, baseline=inputs.baseline)
            out[sid] = {"fired": det.fired, "signals": sorted(det.signals), "risk": det.risk, "band": det.band,
                        "n_records": det.n_records, "tier": det.tier}
    return out


def _volume_facts(m: dict[str, Any]) -> dict[str, Any]:
    """Cover volume (records read by the actor in the scenario) against the owner's own p95, as the node computes it."""
    from app.db.session import SessionLocal
    from app.orchestration import assembly
    from app.services import pg_data

    now = datetime.fromisoformat(m["end"]) + timedelta(seconds=1)
    start, _ = assembly.window_bounds(now.isoformat(), 48)
    with SessionLocal() as db:
        totals = pg_data.fetch_daily_record_totals(db, m["colleague"], start - timedelta(days=30), start) if m.get("colleague") else {}
    p95 = pg_data.percentile(list(totals.values()), 0.95)
    return {"owner_history_days": len(totals), "owner_p95_daily_records": None if p95 is None else round(p95, 1)}


def _event(events: list[dict[str, Any]], node: str, kind: str) -> dict[str, Any] | None:
    return next((e["payload_json"] for e in events if e["node"] == node and e["kind"] == kind), None)


def _run_case(sid: str, m: dict[str, Any], rec: Recorder, preflight: dict[str, Any]) -> dict[str, Any]:
    from app.services import detection

    now = datetime.fromisoformat(m["end"]) + timedelta(seconds=1)
    rec.current = sid
    first_call, t0 = len(rec.calls), time.monotonic()
    det = detection.process_actor(m["actor"], now)
    finished = _wait_for_case_threads()
    cover = _q("SELECT coalesce(sum(records), 0) AS n FROM access_events WHERE actor_id = :a AND action = 'view' AND outcome = "
               "'allowed' AND detail->>'event_ref' LIKE :p", a=m["actor"], p=f"ev-{sid.lower()}-%")[0]["n"]
    row: dict[str, Any] = {
        "id": sid, "group": "genuine" if sid in GENUINE else "forged" if sid in FORGED else "context",
        "actor": m["actor"], "colleague": m.get("colleague"), "is_attack": bool(m["is_attack"]),
        "expected_route": m["expected_route"], "manifest_verdict": m.get("expected_verdict"),
        "cover_records": int(cover), **_volume_facts(m), "preflight": preflight.get(sid),
        "detection": {k: det.get(k) for k in ("action", "risk", "band")}, "case_id": det.get("case_id"),
        "thread_finished": finished, "seconds": round(time.monotonic() - t0, 1)}
    if det.get("case_id") is None:
        row.update(status="no_case", outcome="no_case")
        return row
    cid = det["case_id"]
    case = _q("SELECT status FROM cases WHERE id = :c", c=cid)[0]
    events = _q("SELECT node, kind, payload_json FROM case_events WHERE case_id = :c ORDER BY id", c=cid)
    route, just = _event(events, "route", "decision"), _event(events, "justification", "done")
    cls, rep = _event(events, "classify", "done"), _event(events, "report_writer", "done")
    alert = _q("SELECT rules, risk_score FROM alerts WHERE id = :a", a=det["alert_id"])[0]
    drafts = _q("SELECT body_redacted FROM sar_drafts WHERE case_id = :c ORDER BY version DESC LIMIT 1", c=cid)
    body = drafts[0]["body_redacted"] if drafts else None
    failed = (just or {}).get("failed_checks") or []
    row.update(
        status=case["status"], rules=sorted(alert["rules"] or []), score=round(float(alert["risk_score"] or 0) * 100, 1),
        route_action=(route or {}).get("action"), band=(route or {}).get("band"), blockers=(route or {}).get("blockers"),
        llm_verdict=(just or {}).get("llm_verdict"), final_verdict=(just or {}).get("verdict"),
        corroboration_ok=(just or {}).get("corroboration_ok"), failed_checks=failed,
        blocked_by_volume=VOLUME_CODE in failed, blocked_by_other_checks=[c for c in failed if c != VOLUME_CODE],
        gate_reasons=(just or {}).get("gate_reasons"), classify_scenario=(cls or {}).get("scenario"),
        report_narrative_source=(rep or {}).get("narrative_source"),
        report_contract_errors=validate(body, STORED_REPORT_SCHEMA)[:6] if body else ["no stored report"],
        audit_errors=[f"{e['node']}: {json.dumps(e['payload_json'], default=str)[:160]}" for e in events if e["kind"] == "error"],
        real_report_model=sid in REAL_REPORT_CASES,
        outcome="auto_resolved" if case["status"] == "auto_resolved" else "promoted" if case["status"] == "awaiting_review"
        else f"other:{case['status']}")
    # after our decoding / guards / normalisation: was the stored artefact well-formed?
    repaired = {"justify": (just or {}).get("llm_verdict") in VERDICTS, "classify": (cls or {}).get("scenario") in SCENARIOS,
                "incident_report": (rep or {}).get("narrative_source") == "llm" and not row["report_contract_errors"]}
    for call in rec.calls[first_call:]:
        if call["ok"]:
            call["valid_after_repair"] = repaired[call["schema"]]
    row["real_calls"] = [{k: c[k] for k in ("schema", "model", "ok", "seconds", "input_tokens", "output_tokens") if k in c}
                         for c in rec.calls[first_call:]]
    return row


def _rate(n: int, d: int) -> str:
    return f"{n}/{d} = {100 * n / d:.1f}%" if d else "n/a (0 replies)"


def _summarise(rows: list[dict[str, Any]], rec: Recorder, elapsed: float, info: dict[str, Any]) -> dict[str, Any]:
    by = {r["id"]: r for r in rows}
    genuine = [by[s] for s in GENUINE if s in by]
    forged = [by[s] for s in FORGED if s in by]
    attacks = [r for r in rows if r["is_attack"]]
    fooled = [r for r in attacks if r.get("llm_verdict") == "justified"]
    fooled_blocked = [r for r in fooled if r["outcome"] != "auto_resolved"]
    replies = [c for c in rec.calls if c["ok"]]
    schema_stats: dict[str, Any] = {}
    for key in (*SCHEMAS, "all"):
        sel = [c for c in replies if key == "all" or c["schema"] == key]
        schema_stats[key] = {
            "replies": len(sel), "valid_as_returned": sum(1 for c in sel if c.get("valid_as_returned")),
            "valid_after_repair": sum(1 for c in sel if c.get("valid_after_repair")),
            "invalid_as_returned_cases": sorted({c["case"] for c in sel if not c.get("valid_as_returned")})}
    return {
        "genuine_auto_resolved": f"{sum(r['outcome'] == 'auto_resolved' for r in genuine)}/{len(genuine)}",
        "genuine_auto_resolved_ids": [r["id"] for r in genuine if r["outcome"] == "auto_resolved"],
        "genuine_blocked_by": {r["id"]: [*(r.get("failed_checks") or []), *(r.get("gate_reasons") or [])] for r in genuine
                               if r["outcome"] != "auto_resolved"},
        "forged_refused": f"{sum(r['outcome'] != 'auto_resolved' for r in forged)}/{len(forged)}",
        "forged_refused_as_incident_review": f"{sum(r['outcome'] == 'promoted' for r in forged)}/{len(forged)}",
        "forged_blocked_by_volume_alone": [r["id"] for r in forged if r.get("blocked_by_volume")],
        "forged_blocked_by_the_ticket_checks": [r["id"] for r in forged if r.get("blocked_by_other_checks")],
        "false_auto_resolves": sum(r["outcome"] == "auto_resolved" for r in attacks),
        "attack_cases": len(attacks),
        "model_said_justified_on_an_attack": [r["id"] for r in fooled],
        "model_fooled": len(fooled), "code_blocked_of_those": len(fooled_blocked),
        "schema": schema_stats,
        "real_model_replies": len(replies), "provider_errors": [c for c in rec.calls if not c["ok"]],
        "cache_hits_not_counted": rec.cache_hits, "report_calls_not_made_for": sorted(set(rec.skipped_reports)),
        "tokens_in": sum(c.get("input_tokens") or 0 for c in replies), "tokens_out": sum(c.get("output_tokens") or 0 for c in replies),
        "elapsed_seconds": round(elapsed, 1), **info,
    }


def _section_lines(label: str, section: dict[str, Any]) -> list[str]:
    summary, rows = section["summary"], section["cases"]
    s = summary["schema"]
    lines = [
        "=" * 118,
        SECTION_TITLES.get(label, label),
        f"run at {summary['run_at_utc']} UTC | database {summary['database']} | light model {summary['model_light']} | "
        f"heavy model {summary['model_heavy']}",
        "path: loaded events -> detection.process_actor -> real compiled graph -> real JUSTIFY and CLASSIFY (light model); "
        "REPORT (heavy model) only for " + ", ".join(summary["real_report_cases"]),
        "",
        f"Genuine covers auto-resolved      {summary['genuine_auto_resolved']}   {summary['genuine_auto_resolved_ids'] or ''}",
        f"Forged tickets refused            {summary['forged_refused']}   (promoted to a human: "
        f"{summary['forged_refused_as_incident_review']}; volume check fails for {summary['forged_blocked_by_volume_alone']}; "
        f"ticket checks fail for {summary['forged_blocked_by_the_ticket_checks']})",
        f"False auto-resolves (must be 0)   {summary['false_auto_resolves']}   (over {summary['attack_cases']} attack cases)",
        f"Real model said 'justified' on an attack case: {summary['model_fooled']} {summary['model_said_justified_on_an_attack'] or ''};"
        f" code blocked {summary['code_blocked_of_those']} of them",
        "",
        "Schema-valid share of real model replies:  as returned  |  after our decoding and checks",
    ]
    for key in ("justify", "classify", "incident_report", "all"):
        v = s[key]
        lines.append(f"  {'combined' if key == 'all' else SHORT[key]:9} {_rate(v['valid_as_returned'], v['replies']):22} | "
                     f"{_rate(v['valid_after_repair'], v['replies'])}")
    lines += [
        f"Real model replies {summary['real_model_replies']} | provider errors {len(summary['provider_errors'])} | "
        f"cache hits (not counted) {len(summary['cache_hits_not_counted'])} | tokens in {summary['tokens_in']}, out "
        f"{summary['tokens_out']} | elapsed {summary['elapsed_seconds']} s",
        "",
        f"{'case':5}{'group':8}{'attack':7}{'score':>6}{'  cover':>7}{'  owner p95':>11}  {'model said':13}{'final':14}"
        f"{'outcome':14}checks that failed",
    ]
    for r in rows:
        why = ",".join([*(r.get("failed_checks") or []), *(r.get("gate_reasons") or [])]) or "-"
        lines.append(f"{r['id']:5}{r['group']:8}{str(r['is_attack']):7}{r.get('score', '-')!s:>6}{r['cover_records']:>7}"
                     f"{r.get('owner_p95_daily_records')!s:>11}  {r.get('llm_verdict') or '-':13}{r.get('final_verdict') or '-':14}"
                     f"{r['outcome']:14}{why}")
    return lines


QUOTE_VARIANT = "as_generated"  # the numbers to quote until the generator is fixed and the world regenerated


def slide_numbers(label: str, summary: dict[str, Any]) -> dict[str, Any]:
    """The flat, stable keys that GET /api/quality, the slide and the defense notes read."""
    schema = summary["schema"]["all"]
    forged_ids = set(FORGED)
    return {
        "data_variant": label,
        "genuine_covers_auto_resolved": int(summary["genuine_auto_resolved"].split("/")[0]),
        "genuine_covers_total": int(summary["genuine_auto_resolved"].split("/")[1]),
        "forged_tickets_refused": int(summary["forged_refused"].split("/")[0]),
        "forged_tickets_total": int(summary["forged_refused"].split("/")[1]),
        "false_auto_resolves": summary["false_auto_resolves"], "attack_cases_run": summary["attack_cases"],
        "model_said_justified_on_forged": len(forged_ids & set(summary["model_said_justified_on_an_attack"])),
        "model_said_justified_on_attacks": summary["model_fooled"], "code_blocked_of_those": summary["code_blocked_of_those"],
        "schema_valid_rate": round(schema["valid_as_returned"] / schema["replies"], 4) if schema["replies"] else None,
        "schema_valid_rate_after_repair": round(schema["valid_after_repair"] / schema["replies"], 4) if schema["replies"] else None,
        "schema_valid_by_call": {k: {"as_returned": f"{v['valid_as_returned']}/{v['replies']}",
                                     "after_repair": f"{v['valid_after_repair']}/{v['replies']}"}
                                 for k, v in summary["schema"].items() if k != "all"},
        "total_real_calls": summary["real_model_replies"], "provider_errors": len(summary["provider_errors"]),
        "tokens_in": summary["tokens_in"], "tokens_out": summary["tokens_out"], "elapsed_seconds": summary["elapsed_seconds"],
        "run_at_utc": summary["run_at_utc"], "light_model": summary["model_light"], "heavy_model": summary["model_heavy"],
        "cases_run": len(summary["cases_run"]),
    }


def _assertions_failed(sections: dict[str, Any]) -> list[str]:
    """Invariants of the live run: no attack case is auto-resolved, and every case ended in a decided state."""
    failed: list[str] = []
    for label, sec in sections.items():
        for row in sec["cases"]:
            if row["is_attack"] and row["outcome"] == "auto_resolved":
                failed.append(f"{label}: {row['id']} is an attack case and was auto-resolved")
            if row["outcome"] not in ("auto_resolved", "promoted"):
                failed.append(f"{label}: {row['id']} ended as {row['outcome']}")
    return failed


def top_level(sections: dict[str, Any]) -> dict[str, Any]:
    """The three keys GET /api/quality reads (scenarios list, metrics object, assertions_failed list) plus the full sections.
    metrics holds the quoted variant's flat numbers, and every variant's under its own key."""
    variants = {label: slide_numbers(label, sec["summary"]) for label, sec in sections.items()}
    quote = QUOTE_VARIANT if QUOTE_VARIANT in sections else next(iter(sections))
    metrics: dict[str, Any] = {**variants[quote], "quote_variant": quote}
    for label, numbers in variants.items():
        metrics["volume_adjusted" if label == "volume_adjusted_local_copy" else label] = numbers
    metrics["note"] = ("as_generated is what pg_generate wrote: the covers read more than their owner's p95, so the volume check "
                       "blocks every cover. volume_adjusted is a local copy with cover views trimmed to the owner's p95; "
                       "it is not the generator's output. Quote as_generated until the generator is fixed.")
    return {"scenarios": [r for r in sections[quote]["cases"]], "metrics": metrics,
            "assertions_failed": _assertions_failed(sections), "sections": sections}


def write_files(label: str | None = None, section: dict[str, Any] | None = None) -> None:
    """Store this run as section `label` (if given) and re-render the text table from every stored section."""
    data = json.loads(OUT_JSON.read_text(encoding="utf-8")) if OUT_JSON.exists() else {}
    sections = data.get("sections", {})
    if label is not None and section is not None:
        sections[label] = section
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(top_level(sections), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    lines = ["PolicyGuard live golden set (real models, full world). Numbers are exactly what the code produced.", ""]
    for key in [k for k in SECTION_TITLES if k in sections] + [k for k in sections if k not in SECTION_TITLES]:
        lines += _section_lines(key, sections[key]) + [""]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


def run(data: Path, fresh_cache: bool, only: list[str] | None, *, label: str = "as_generated", replace_events: bool = False,
        preflight_only: bool = False) -> int:
    """Returns 0 when no attack was auto-resolved, 1 when one was, 2 when live mode is not configured."""
    try:
        from app.config import get_settings
        from app.db.session import SessionLocal, engine

        settings = get_settings()
        if settings.llm_provider != "groq" or not settings.llm_model_light or not settings.llm_model_heavy:
            raise RuntimeError("LLM_PROVIDER must be groq and LLM_MODEL_LIGHT / LLM_MODEL_HEAVY set")
        if not settings.groq_api_key:
            raise RuntimeError("no GROQ_API_KEY")
        with SessionLocal() as probe:
            agents_n = probe.execute(text("SELECT count(*) FROM agents")).scalar_one()
            events_n = probe.execute(text("SELECT count(*) FROM access_events")).scalar_one()
        if agents_n < 100 or events_n < 100_000:
            raise RuntimeError(f"the full world is not loaded (agents={agents_n}, access_events={events_n}); "
                               "run: python -m app.ingest.pg_load data/policyguard --reset")
        manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))["scenarios"]
        cases = [c for c in ALL_CASES if not only or c in only]
        missing = [c for c in cases if c not in manifest]
        if missing:
            raise RuntimeError(f"not in the manifest: {missing} (generate the full world with pg_generate --out)")
    except Exception as exc:  # noqa: BLE001  any problem means live mode is not configured
        print(f"live mode not configured: {type(exc).__name__}: {str(exc)[:240]}")
        return 2

    print(f"database {engine.url.database}, section {label}, {len(cases)} cases, light={settings.llm_model_light} "
          f"heavy={settings.llm_model_heavy}")
    with SessionLocal() as db:
        if fresh_cache and not preflight_only:
            print("llm_cache rows deleted:", db.execute(text("DELETE FROM llm_cache")).rowcount)
        if not preflight_only:
            superseded = db.execute(text("UPDATE cases SET status = 'superseded' WHERE account_id = ANY(:a) AND status IN "
                                         "('open','awaiting_review','auto_resolved','closed','approved')"),
                                    {"a": [manifest[c]["actor"] for c in cases]}).rowcount
            print("earlier cases of these actors marked superseded:", superseded)
        db.commit()
    print("scenario events:", _ensure_events(data, cases, replace_events))
    pre = _preflight(manifest, cases)
    for sid in cases:
        print(f"preflight {sid:4} {pre[sid]}")
    if preflight_only:
        return 0

    rec = Recorder()
    rec.install()
    rows: list[dict[str, Any]] = []
    t_start = time.monotonic()
    try:
        for sid in cases:
            row = _run_case(sid, manifest[sid], rec, pre)
            rows.append(row)
            print(f"{sid:4} attack={str(row['is_attack']):5} score={row.get('score', '-')!s:>5} cover={row['cover_records']:>3} "
                  f"p95={row.get('owner_p95_daily_records')!s:>6} llm={row.get('llm_verdict')!s:12} "
                  f"final={row.get('final_verdict')!s:12} outcome={row['outcome']:13} {row['seconds']}s "
                  f"why={row.get('failed_checks')}{row.get('gate_reasons')}", flush=True)
    finally:
        rec.uninstall()
    elapsed = time.monotonic() - t_start

    info = {"run_at_utc": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"), "database": engine.url.database,
            "model_light": settings.llm_model_light, "model_heavy": settings.llm_model_heavy,
            "path": "access_events -> detection.process_actor -> compiled LangGraph (Postgres checkpointer) -> real models",
            "data_dir": str(data), "real_report_cases": sorted(REAL_REPORT_CASES & set(cases)), "cases_run": cases}
    summary = _summarise(rows, rec, elapsed, info)
    write_files(label, {"summary": summary, "cases": rows, "calls": rec.calls})
    print("-" * 100)
    print("\n".join(_section_lines(label, {"summary": summary, "cases": rows})))
    print(f"written: {OUT_JSON}\n         {OUT_MD}")
    return 1 if summary["false_auto_resolves"] else 0
