"""Where the portal reads actors and records and writes access events.

Two stores with one interface:
- MemoryStore: the generator's JSON files (tests/fixtures/pg_small or data/policyguard). No database. For tests and
  local development before migration 0011 exists. Events are kept in memory.
- DbStore: the PolicyGuard tables (migrations 0011 and 0012), reflected at first use and mapped by column name:
    agents(agent_id, hr_status, credential_enabled)      partner_keys(key_id, enabled)
    parties(account_id, name, product, city)            partner_claim_assignments(key_id, claim_id)
    access_events(id bigint, ts, actor_id, actor_type, action, resource_type, resource_id, policyholder_id, tier,
                  records, outcome, channel, ip, device, city, session_id, labels, detail, country)
  A claim exists when it is assigned to some partner key (every claim is assigned to exactly one TPA). The
  database assigns access_events.id (the evidence ID); the caller's event reference goes into detail.event_ref.
  `labels` stays ground truth only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol


class PortalStore(Protocol):
    def agent(self, agent_id: str) -> dict[str, Any] | None: ...
    def partner_key(self, key_id: str) -> dict[str, Any] | None: ...
    def policyholder(self, policyholder_id: str) -> dict[str, Any] | None: ...
    def claim(self, claim_id: str) -> dict[str, Any] | None: ...
    def search(self, filters: dict[str, str], text: str, limit: int) -> list[dict[str, Any]]: ...
    def record(self, event: dict[str, Any]) -> None: ...


class StoreNotReady(RuntimeError):
    """The PolicyGuard tables are not there yet (migration 0011 not applied)."""


# ---------------------------------------------------------------------------------------------- memory (fixture)
class MemoryStore:
    def __init__(self, agents: dict, partner_keys: dict, policyholders: dict, claims: dict):
        self.agents, self.partner_keys, self.policyholders, self.claims = agents, partner_keys, policyholders, claims
        self.events: list[dict[str, Any]] = []

    @classmethod
    def from_dir(cls, path: str | Path) -> "MemoryStore":
        p = Path(path)

        def lines(name: str) -> list[dict]:
            with open(p / name, encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]

        agents = {a["agent_id"]: a for a in json.loads((p / "agents.json").read_text(encoding="utf-8"))}
        keys = {k["key_id"]: k for k in json.loads((p / "partner_keys.json").read_text(encoding="utf-8"))}
        phs = {r["policyholder_id"]: r for r in lines("policyholders.jsonl")}
        claims = {c["claim_id"]: c for c in lines("claims.jsonl")}
        return cls(agents, keys, phs, claims)

    def agent(self, agent_id):
        return self.agents.get(agent_id)

    def partner_key(self, key_id):
        return self.partner_keys.get(key_id)

    def policyholder(self, policyholder_id):
        return self.policyholders.get(policyholder_id)

    def claim(self, claim_id):
        return self.claims.get(claim_id)

    def search(self, filters, text, limit):
        out = []
        for ph in self.policyholders.values():
            if all(str(ph.get(k, "")).lower() == v.lower() for k, v in filters.items()) and \
                    (not text or text.lower() in ph["name"].lower()):
                out.append(ph)
                if len(out) >= limit:
                    break
        return out

    def record(self, event):
        self.events.append(dict(event))


# ---------------------------------------------------------------------------------------------- database
class DbStore:
    """Reflects the PolicyGuard tables once per process and maps rows by column name."""

    _tables: dict[str, Any] | None = None

    def __init__(self, db):
        self.db = db

    def _t(self, name: str):
        if DbStore._tables is None:
            from sqlalchemy import MetaData, inspect

            insp = inspect(self.db.get_bind())
            present = set(insp.get_table_names())
            md = MetaData()
            wanted = [t for t in ("agents", "partner_keys", "parties", "partner_claim_assignments", "access_events")
                      if t in present]
            md.reflect(bind=self.db.get_bind(), only=wanted)
            DbStore._tables = dict(md.tables)
        t = DbStore._tables.get(name)
        if t is None:
            raise StoreNotReady(f"table {name} not found: apply migration 0011 (alembic upgrade head)")
        return t

    def _one(self, table: str, key_col: str, value: str) -> dict[str, Any] | None:
        from sqlalchemy import select

        t = self._t(table)
        row = self.db.execute(select(t).where(t.c[key_col] == value)).mappings().first()
        return dict(row) if row else None

    def agent(self, agent_id):
        return self._one("agents", "agent_id", agent_id)

    def partner_key(self, key_id):
        return self._one("partner_keys", "key_id", key_id)

    def policyholder(self, policyholder_id):
        row = self._one("parties", "account_id", policyholder_id)
        if row is not None:
            row.setdefault("policyholder_id", row.get("account_id"))
        return row

    def claim(self, claim_id):
        row = self._one("partner_claim_assignments", "claim_id", claim_id)
        return {"claim_id": claim_id, "tpa_key": row["key_id"]} if row else None

    def search(self, filters, text, limit):
        from sqlalchemy import func, select

        t = self._t("parties")
        q = select(t)
        for k, v in filters.items():
            if k in t.c:
                q = q.where(func.lower(t.c[k]) == v.lower())
        if text:
            q = q.where(t.c["name"].ilike(f"%{text}%"))
        rows = self.db.execute(q.limit(limit)).mappings().all()
        return [{**dict(r), "policyholder_id": r.get("account_id")} for r in rows]

    def record(self, event):
        t = self._t("access_events")
        cols = set(t.c.keys())
        row = {k: v for k, v in event.items() if k in cols and k != "id"}
        row["labels"] = event.get("labels") or {}
        if "detail" in cols:
            row["detail"] = {**(event.get("detail") or {}), "event_ref": event["event_id"]}
        if "ts" in row and isinstance(row["ts"], str):
            from datetime import datetime

            row["ts"] = datetime.fromisoformat(row["ts"])
        new_id = self.db.execute(t.insert().values(**row).returning(t.c.id)).scalar_one()
        self.db.commit()
        event["id"] = new_id
