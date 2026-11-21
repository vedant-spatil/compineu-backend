"""Load the generator's files (app/ingest/pg_generate.py) into the PolicyGuard tables (migrations 0011 and 0012).

    python -m app.ingest.pg_load data/policyguard --reset            # full world, replacing earlier demo data
    python -m app.ingest.pg_load tests/fixtures/pg_small --reset     # small fixture
    python -m app.ingest.pg_load data/policyguard --scenarios S1,S1b # also insert these scenarios as recorded

Tables: parties (policyholders, PH-*), agents (agents and branch managers), portfolios, partner_keys,
partner_claim_assignments, context_records, access_events (history, plus any --scenarios). Big tables go through
Postgres COPY. --reset deletes earlier PolicyGuard demo rows first (never cases, alerts or the audit trail).

Scenario events normally reach the database through the replay, which calls the mock portal so the whole path runs.
--scenarios inserts them directly with their recorded timestamps, for a quick check of detection.
Every row keeps the generator's reference: context_records.payload.ref (LV-221, TKT-4471) and access_events.detail.
event_ref (ev-s1-00001). The database assigns the integer ids that evidence cites.
"""
from __future__ import annotations

import argparse
import json
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import text

from app.db.session import engine

EVENT_COLS = ["ts", "actor_id", "actor_type", "action", "resource_type", "resource_id", "policyholder_id", "tier",
              "records", "outcome", "channel", "ip", "device", "city", "session_id", "labels", "detail", "country"]
RESET_SQL = [
    "DELETE FROM access_events",
    "DELETE FROM portfolios",
    "DELETE FROM partner_claim_assignments",
    "DELETE FROM partner_keys",
    "DELETE FROM context_records",
    "DELETE FROM agents",
    "DELETE FROM parties WHERE account_id LIKE 'PH-%'",
]


def _lines(path: Path) -> Iterable[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _json(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def event_row(e: dict[str, Any]) -> tuple:
    detail = {**(e.get("detail") or {}), "event_ref": e["event_id"]}
    return (e["ts"], e["actor_id"], e["actor_type"], e["action"], e["resource_type"], e["resource_id"] or "-",
            e.get("policyholder_id"), e.get("tier") or "T3", int(e.get("records", 0)), e["outcome"], e["channel"],
            e.get("ip"), e.get("device"), e.get("city"), e.get("session_id"), _json(e.get("labels") or {}),
            _json(detail), e.get("country"))


def _copy(cur, table: str, cols: list[str], rows: Iterable[tuple]) -> int:
    n = 0
    with cur.copy(f"COPY {table} ({', '.join(cols)}) FROM STDIN") as cp:
        for r in rows:
            cp.write_row(r)
            n += 1
    return n


def load(src: Path, reset: bool = False, scenarios: list[str] | None = None) -> dict[str, int]:
    agents = json.loads((src / "agents.json").read_text(encoding="utf-8"))
    keys = json.loads((src / "partner_keys.json").read_text(encoding="utf-8"))
    context = json.loads((src / "context_records.json").read_text(encoding="utf-8"))
    counts: dict[str, int] = {}

    raw = engine.raw_connection()
    try:
        conn = raw.driver_connection  # psycopg 3 connection: COPY support
        with conn.cursor() as cur:
            if reset:
                for sql in RESET_SQL:
                    cur.execute(sql)
            counts["parties"] = _copy(cur, "parties", ["account_id", "name", "dob", "country", "planted", "product", "city"],
                                      ((p["policyholder_id"], p["name"], p["dob"], p.get("country", "IN"), False,
                                        p.get("product"), p.get("city")) for p in _lines(src / "policyholders.jsonl")))
            counts["agents"] = _copy(
                cur, "agents", ["agent_id", "name", "branch", "channel", "hr_status", "credential_enabled", "manager_id",
                                "usual_start_hour", "usual_end_hour", "home_city", "known_devices"],
                ((a["agent_id"], a["name"], a["branch"], a["channel"], a["hr_status"], a["credential_enabled"],
                  a.get("manager_id"), a["usual_start_hour"], a["usual_end_hour"], a["home_city"],
                  _json(a.get("known_devices", []))) for a in agents))
            counts["portfolios"] = _copy(cur, "portfolios", ["agent_id", "policyholder_id"],
                                         ((r["agent_id"], r["policyholder_id"]) for r in _lines(src / "portfolios.jsonl")))
            counts["partner_keys"] = _copy(cur, "partner_keys", ["key_id", "partner", "enabled", "known_ips"],
                                           ((k["key_id"], k["partner"], k["enabled"], _json(k.get("known_ips", [])))
                                            for k in keys))
            counts["partner_claim_assignments"] = _copy(
                cur, "partner_claim_assignments", ["key_id", "claim_id"],
                ((k["key_id"], c) for k in keys for c in k.get("assigned_claims", [])))
            counts["context_records"] = _copy(
                cur, "context_records", ["type", "subject_agent", "named_agent", "created_by", "created_at",
                                         "valid_from", "valid_to", "payload"],
                ((c["type"], c["subject_agent"], c.get("named_agent"), c["created_by"], c["created_at"],
                  c.get("valid_from"), c.get("valid_to"), _json(c["payload"])) for c in context))
            counts["access_events_history"] = _copy(cur, "access_events", EVENT_COLS,
                                                    (event_row(e) for e in _lines(src / "history.jsonl")))
            for sid in scenarios or []:
                counts[f"access_events_{sid}"] = _copy(cur, "access_events", EVENT_COLS,
                                                       (event_row(e) for e in _lines(src / "scenarios" / f"{sid}.jsonl")))
        conn.commit()
    except Exception:
        raw.driver_connection.rollback()
        raise
    finally:
        raw.close()
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Load PolicyGuard generator output into the database.")
    ap.add_argument("src", type=Path, help="generator output directory (data/policyguard or tests/fixtures/pg_small)")
    ap.add_argument("--reset", action="store_true", help="delete earlier PolicyGuard demo rows first")
    ap.add_argument("--scenarios", default="", help="comma-separated scenario IDs to insert directly (e.g. S1,S1b)")
    args = ap.parse_args()
    t0 = time.monotonic()
    counts = load(args.src, args.reset, [s for s in args.scenarios.split(",") if s])
    with engine.connect() as c:
        events = c.execute(text("SELECT count(*) FROM access_events")).scalar_one()
    print(f"loaded {args.src} in {time.monotonic() - t0:.1f}s: " + ", ".join(f"{k}={v}" for k, v in counts.items())
          + f" (access_events now {events})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
