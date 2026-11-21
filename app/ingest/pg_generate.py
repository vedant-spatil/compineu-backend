"""PolicyGuard synthetic world and labelled scenarios (plan section 8; combined plan sections 5, 7, 12).

Standard library only, seed 42, fully deterministic. Writes JSON files that the loader maps onto the 0011 tables, so it
does not depend on the database schema being final.

    python -m app.ingest.pg_generate --out data/policyguard            # full: 50,000 policyholders, 200 agents, 30 days
    python -m app.ingest.pg_generate --fixture tests/fixtures/pg_small  # small: scenario actors only, 7 days of history

Conventions
- Timestamps are plain UTC without a timezone ("2026-11-20T18:08:41"), like alerts.ts. Agents work 10:00-19:00 IST
  (04:30-13:30 UTC). The demo day is 2026-11-20; history covers the 30 days before it.
- Tiers: T1 = health policyholder profile or claim file (diagnoses, claim amounts); T2 = motor/life profile or policy.
- `labels` (scenario, is_attack) exist only for scoring. Detectors must never read them.
- Every scenario event also carries `offset_s` from the scenario start, so the replay can shift it to "now".
- Searches carry records=0: they list names only. Each record opened is its own `view` event, so A1 can check every
  policyholder against the portfolio. Exports carry the row count in `records`.

Scenarios (expected values are the plan's worked examples; report what detection actually produces)
  S1   AG-1147's bad night: new device + city at 23:38 IST, 1,840 out-of-portfolio records (T1), 1,200-row export -> ~89
  S1b  Anita covers Priya (approved leave + ticket by their manager, no servicing assignment): 130 T2 -> ~54, justified
  S1c  Dev writes his own "approved" ticket to read Raj's customers, no leave: 130 T2 -> ~54, refused and promoted
  S1d  Kiran reads Meena's customers; Meena is really on leave but the ticket is Kiran's own: 170 T2 -> ~55, refused
  S2   CareLink TPA key from a new country: sequential claim IDs, ~70% 404, 420 unassigned claims returned -> ~95
  S5   AG-0577 terminated yesterday, credential still enabled, reads 40 own T2 records -> ~50, floor lifts to 60
  D1   Branch manager MG-014 reviews 300 of the team's T2 records in an hour -> ~41, Medium, no incident (benign)
  D2   AG-1055 serves 40 of AG-1056's customers under a servicing assignment -> no A1 (benign)
  D3   Renewal-campaign volume spike on own portfolio under approval AP-12 -> ~39, logged only (benign)
  D4   CareLink's approved night batch from its known IP on assigned claims (benign)
  EG1-EG8 / EF1-EF5 (full only): 8 genuine covers (leave + manager ticket), 5 forged tickets, for the golden set
"""
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

SEED = 42
DEMO_DAY = date(2026, 11, 20)
HISTORY_DAYS = 30
IST = timedelta(hours=5, minutes=30)
PORTFOLIO_SIZE = 250

BRANCHES = [  # (branch, city); manager MG-011 + index, so PUNE-01 -> MG-014 as in the plan's examples
    ("MUMBAI-01", "Mumbai"), ("MUMBAI-02", "Mumbai"), ("THANE-01", "Thane"), ("PUNE-01", "Pune"),
    ("PUNE-02", "Pune"), ("NASHIK-01", "Nashik"), ("NAGPUR-01", "Nagpur"), ("AURANGABAD-01", "Aurangabad"),
    ("BENGALURU-01", "Bengaluru"), ("HYDERABAD-01", "Hyderabad"), ("DELHI-01", "Delhi"), ("LUCKNOW-01", "Lucknow"),
]
MANAGER = {b: f"MG-{11 + i:03d}" for i, (b, _) in enumerate(BRANCHES)}
CITY = dict(BRANCHES)

FIRST_F = ["Anita", "Priya", "Meena", "Kavya", "Sneha", "Pooja", "Neha", "Divya", "Swati", "Asha", "Rekha", "Lata",
           "Sunita", "Shruti", "Aditi", "Ishita", "Nisha", "Rupali", "Manisha", "Vaishali", "Smita", "Jyoti", "Komal",
           "Rashmi", "Deepa", "Harini", "Lakshmi", "Pallavi", "Ritu", "Sonal"]
FIRST_M = ["Dev", "Raj", "Kiran", "Amit", "Rahul", "Suresh", "Vikram", "Arjun", "Rohan", "Sanjay", "Manoj", "Nitin",
           "Prakash", "Ajay", "Vijay", "Sameer", "Anil", "Ravi", "Ganesh", "Mahesh", "Sachin", "Tushar", "Omkar",
           "Yogesh", "Harsh", "Aditya", "Karan", "Varun", "Imran", "Farhan"]
SURNAMES = ["Kulkarni", "Deshpande", "Patil", "Joshi", "Shinde", "Pawar", "Jadhav", "Gaikwad", "Sharma", "Verma",
            "Gupta", "Iyer", "Nair", "Reddy", "Rao", "Menon", "Shah", "Mehta", "Desai", "Chavan", "Bhosale", "More",
            "Kale", "Naik", "Khan", "Qureshi", "Singh", "Yadav", "Mishra", "Pandey", "Agarwal", "Bansal", "Saxena",
            "Tiwari", "Dubey", "Kapoor", "Malhotra", "Bose", "Das", "Sen"]
FOCUS_MIX = {"motor": (0.70, 0.15, 0.15), "health": (0.15, 0.70, 0.15), "life": (0.20, 0.20, 0.60),
             "mixed": (0.45, 0.40, 0.15)}  # (motor, health, life)
TPAS = [("PK-CARELINK", "CareLink TPA", "203.0.113.10"), ("PK-HEALTHBRIDGE", "HealthBridge TPA", "203.0.113.11"),
        ("PK-MEDISURE", "MediSure TPA", "203.0.113.12")]

# Named actors from the plan. Everyone else is drawn deterministically from AG-0501..AG-1200.
NAMED = {
    "AG-1147": dict(name="Rohit Patil", branch="PUNE-02", focus="motor", daily=34),           # S1
    "AG-1033": dict(name="Anita Deshpande", branch="PUNE-01", focus="mixed", daily=30),       # S1b subject
    "AG-0932": dict(name="Priya Joshi", branch="PUNE-01", focus="motor", daily=110),          # S1b colleague (renewals)
    "AG-1088": dict(name="Dev Sharma", branch="MUMBAI-01", focus="mixed", daily=30),         # S1c subject
    "AG-1090": dict(name="Raj Mehta", branch="MUMBAI-01", focus="motor", daily=110),         # S1c colleague
    "AG-1120": dict(name="Kiran Pawar", branch="NASHIK-01", focus="mixed", daily=30),        # S1d subject
    "AG-1121": dict(name="Meena Kale", branch="NASHIK-01", focus="motor", daily=120),        # S1d colleague (on leave)
    "AG-0577": dict(name="Sanjay More", branch="THANE-01", focus="motor", daily=28),          # S5 terminated
    "AG-1055": dict(name="Ganesh Naik", branch="NAGPUR-01", focus="mixed", daily=32),        # D2 assignee
    "AG-1056": dict(name="Swati Bhosale", branch="NAGPUR-01", focus="health", daily=36),     # D2 colleague
    "AG-1012": dict(name="Vikram Shah", branch="MUMBAI-02", focus="motor", daily=40),        # D3 renewal campaign
}
FIXTURE_ACTORS = ["AG-1147", "AG-1033", "AG-0932", "AG-1088", "AG-1090", "AG-1120", "AG-1121", "AG-0577"]
FIXTURE_SCENARIOS = ["S1", "S1b", "S1c", "S1d", "S5"]


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def ist(d: date, hh: int, mm: int = 0, ss: int = 0) -> datetime:
    """An IST wall-clock time as naive UTC."""
    return datetime(d.year, d.month, d.day, hh, mm, ss) - IST


@dataclass
class World:
    rng: random.Random
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    managers: dict[str, dict[str, Any]] = field(default_factory=dict)
    policyholders: dict[str, dict[str, Any]] = field(default_factory=dict)
    portfolios: dict[str, list[str]] = field(default_factory=dict)
    claims: dict[str, dict[str, Any]] = field(default_factory=dict)
    partner_keys: list[dict[str, Any]] = field(default_factory=list)
    context: list[dict[str, Any]] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    scenarios: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    manifest: dict[str, dict[str, Any]] = field(default_factory=dict)
    _ctx_seq: dict[str, int] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers
    def ctx_id(self, prefix: str, start: int) -> str:
        n = self._ctx_seq.get(prefix, start)
        self._ctx_seq[prefix] = n + 1
        return f"{prefix}-{n}"

    def add_ctx(self, type_: str, prefix: str, start: int, subject: str, created_by: str, created_at: datetime,
                payload: dict[str, Any], rid: str | None = None, *, named: str | None = None,
                days: tuple[str, str] | None = None) -> str:
        """One context_records row (0011). `subject` is whose portfolio or leave it is about, `named` who it authorises,
        `days` the IST calendar days it covers (valid_from inclusive, valid_to exclusive, naive UTC). The database
        assigns the integer id; our readable reference (LV-221, TKT-4471) goes into payload.ref."""
        rid = rid or self.ctx_id(prefix, start)
        vf = vt = None
        if days:
            d0, d1 = date.fromisoformat(days[0]), date.fromisoformat(days[1])
            vf, vt = iso(ist(d0, 0)), iso(ist(d1 + timedelta(days=1), 0))
        self.context.append({"ref": rid, "type": type_, "subject_agent": subject, "named_agent": named,
                             "created_by": created_by, "created_at": iso(created_at), "valid_from": vf,
                             "valid_to": vt, "payload": {"ref": rid, **payload}})
        return rid

    def person(self, female: bool | None = None) -> str:
        female = self.rng.random() < 0.5 if female is None else female
        return f"{self.rng.choice(FIRST_F if female else FIRST_M)} {self.rng.choice(SURNAMES)}"

    def tier(self, ph_id: str) -> str:
        return "T1" if self.policyholders[ph_id]["product"] == "health" else "T2"

    def t2_of(self, agent: str) -> list[str]:
        return [p for p in self.portfolios[agent] if self.tier(p) == "T2"]


# ==================================================================== world
def build_world(seed: int = SEED) -> World:
    w = World(rng=random.Random(seed))
    rng = w.rng

    # Agents: 200 in 12 branches. Named agents first, then a deterministic sample of codes.
    pool = [f"AG-{n:04d}" for n in range(501, 1201) if f"AG-{n:04d}" not in NAMED]
    others = sorted(rng.sample(pool, 200 - len(NAMED)))
    branch_cycle = [b for b, _ in BRANCHES]
    for i, aid in enumerate(others):
        branch = branch_cycle[i % len(branch_cycle)]
        w.agents[aid] = dict(name=w.person(), branch=branch, focus=rng.choice(["motor", "motor", "health", "life", "mixed"]),
                             daily=rng.randint(20, 45))
    for aid, spec in NAMED.items():
        w.agents[aid] = dict(spec)
    for aid in sorted(w.agents):
        a = w.agents[aid]
        a.update(agent_id=aid, city=CITY[a["branch"]], channel="agent", role="agent", manager_id=MANAGER[a["branch"]],
                 hr_status="active", credential_enabled=True, usual_hours_ist=[10, 19],
                 known_devices=[f"dv-{rng.getrandbits(16):04x}" for _ in range(rng.choice([1, 1, 2]))],
                 home_ip=f"10.{20 + branch_cycle.index(a['branch'])}.{rng.randint(1, 250)}.{rng.randint(2, 250)}",
                 hired_on=str(DEMO_DAY - timedelta(days=rng.randint(200, 2500))))
    w.agents["AG-0577"]["hr_status"] = "terminated"   # S5: HR terminated him yesterday ...
    w.agents["AG-0577"]["credential_enabled"] = True  # ... but the portal credential was never disabled
    w.agents = dict(sorted(w.agents.items()))

    for b, city in BRANCHES:
        mid = MANAGER[b]
        w.managers[mid] = dict(agent_id=mid, name=w.person(), branch=b, city=city, channel="staff", role="branch_manager",
                               manager_id=None, hr_status="active", credential_enabled=True, usual_hours_ist=[10, 19],
                               known_devices=[f"dv-{rng.getrandbits(16):04x}"],
                               home_ip=f"10.{20 + branch_cycle.index(b)}.0.{rng.randint(2, 250)}", focus="team",
                               daily=15, hired_on=str(DEMO_DAY - timedelta(days=rng.randint(1500, 4000))))

    # Policyholders: exactly 250 per agent (50,000), product mix by the agent's focus, city = branch city.
    n = 0
    for aid, a in w.agents.items():
        mix = FOCUS_MIX[a["focus"]]
        w.portfolios[aid] = []
        for _ in range(PORTFOLIO_SIZE):
            n += 1
            r = rng.random()
            product = "motor" if r < mix[0] else "health" if r < mix[0] + mix[1] else "life"
            pid = f"PH-{n:05d}"
            dob = date(1950, 1, 1) + timedelta(days=rng.randint(0, 365 * 55))
            w.policyholders[pid] = dict(policyholder_id=pid, name=w.person(), dob=str(dob), country="IN",
                                        city=a["city"], branch=a["branch"], product=product, agent_id=aid,
                                        policy_no=f"{product[0].upper()}{rng.randint(10**8, 10**9 - 1)}",
                                        sum_insured=rng.choice([300000, 500000, 1000000, 2500000]))
            w.portfolios[aid].append(pid)
    # Managers' portfolio: the union of their team's portfolios (a manager reviewing the team is not out of portfolio).
    for mid, m in w.managers.items():
        w.portfolios[mid] = [p for aid, a in w.agents.items() if a["branch"] == m["branch"] for p in w.portfolios[aid]]

    # Claims: health policyholders only, sparse IDs (~1 in 3 numbers exists), each assigned to one TPA.
    num = 1_000_000
    for pid, ph in w.policyholders.items():
        if ph["product"] != "health":
            continue
        for _ in range(rng.choices([0, 1, 2], weights=[62, 30, 8])[0]):
            num += rng.randint(1, 5)
            cid = f"CL-{num}"
            w.claims[cid] = dict(claim_id=cid, policyholder_id=pid, tpa_key=rng.choices([t[0] for t in TPAS],
                                 weights=[40, 35, 25])[0], amount=rng.randint(8_000, 900_000),
                                 status=rng.choice(["open", "settled", "settled", "rejected"]))
    for key, partner, ip in TPAS:
        w.partner_keys.append(dict(key_id=key, partner=partner, enabled=True, known_ips=[ip], country="IN",
                                   assigned_claims=sorted(c for c, v in w.claims.items() if v["tpa_key"] == key)))

    build_context(w)
    return w


def build_context(w: World) -> None:
    rng = w.rng
    hr = "HR-001"
    # HR status history (agents.hr_status holds the current value; reporting lines are agents.manager_id).
    for aid, a in w.agents.items():
        until = "2099-12-30" if aid != "AG-0577" else str(DEMO_DAY - timedelta(days=2))
        w.add_ctx("hr_status", "HRS", 1, aid, hr, datetime.fromisoformat(a["hired_on"]), {"status": "active"},
                  days=(a["hired_on"], until))
    w.add_ctx("hr_status", "HRS", 1, "AG-0577", hr, ist(DEMO_DAY - timedelta(days=1), 10),
              {"status": "terminated", "note": "exit processed; portal credential pending IT disable"},
              days=(str(DEMO_DAY - timedelta(days=1)), "2099-12-30"))

    # S1b: Priya on approved leave (approved by her manager MG-014 on Nov 10); the manager's ticket names Anita.
    w.add_ctx("leave", "LV", 221, "AG-0932", "MG-014", ist(date(2026, 11, 10), 14, 30),
              {"employee": "AG-0932", "from": "2026-11-16", "to": "2026-11-22", "approved_by": "MG-014"},
              rid="LV-221", days=("2026-11-16", "2026-11-22"))
    w.add_ctx("ticket", "TKT", 4471, "AG-0932", "MG-014", ist(date(2026, 11, 15), 17, 20),
              {"author_role": "branch_manager",
               "body": "Anita to cover Priya's renewals while she is on leave this week. Please action."},
              rid="TKT-4471", named="AG-1033")
    # S1c: Dev's own ticket about Raj's customers; no leave or transfer for Raj.
    w.add_ctx("ticket", "TKT", 4480, "AG-1090", "AG-1088", ist(DEMO_DAY, 9, 52),
              {"author_role": "agent", "body": "Covering Raj's customers, approved."}, rid="TKT-4480", named="AG-1088")
    # S1d: Meena really is on leave (approved by MG-016), but the ticket is Kiran's own.
    w.add_ctx("leave", "LV", 230, "AG-1121", "MG-016", ist(date(2026, 11, 12), 11, 5),
              {"employee": "AG-1121", "from": "2026-11-17", "to": "2026-11-21", "approved_by": "MG-016"},
              rid="LV-230", days=("2026-11-17", "2026-11-21"))
    w.add_ctx("ticket", "TKT", 4490, "AG-1121", "AG-1120", ist(date(2026, 11, 18), 10, 15),
              {"author_role": "agent", "body": "Covering Meena's renewals while she is on leave, approved by manager."},
              rid="TKT-4490", named="AG-1120")
    # D2: servicing assignment of 40 of AG-1056's customers to AG-1055, created by MG-017 with a ticket.
    d2 = w.portfolios["AG-1056"][:40]
    w.add_ctx("ticket", "TKT", 4460, "AG-1056", "MG-017", ist(date(2026, 11, 17), 16, 0),
              {"author_role": "branch_manager",
               "body": "Ganesh to service 40 of Swati's health renewals until 24 Nov (see SA-301)."},
              rid="TKT-4460", named="AG-1055")
    w.add_ctx("servicing_assignment", "SA", 301, "AG-1056", "MG-017", ist(date(2026, 11, 17), 16, 5),
              {"policyholders": d2, "ticket": "TKT-4460"}, rid="SA-301", named="AG-1055",
              days=("2026-11-18", "2026-11-24"))
    # D3: renewal campaign approval, one row per MUMBAI-02 agent (own portfolio, higher volume allowed).
    # MUMBAI-02, not MUMBAI-01: an approval naming Dev (S1c) would let A1 treat his reads as covered.
    for aid in [a for a, v in w.agents.items() if v["branch"] == "MUMBAI-02"]:
        w.add_ctx("approval", "AP", 12, aid, "MG-012", ist(date(2026, 11, 17), 9, 30),
                  {"scope": "renewal_campaign_nov", "branch": "MUMBAI-02", "max_records_per_day": 400},
                  rid="AP-12", named=aid, days=("2026-11-18", "2026-11-30"))
    # D4: CareLink's approved night batch (subject and named: the partner key).
    w.add_ctx("approval", "AP", 13, "PK-CARELINK", "OPS-002", ist(date(2026, 11, 1), 12),
              {"scope": "tpa_night_batch", "window_ist": "02:00-02:45"}, rid="AP-13", named="PK-CARELINK",
              days=("2026-11-01", "2026-12-31"))

    # Noise: past leaves (agents do not work those days), transfers, benign tickets.
    busy = set(NAMED)
    for aid in rng.sample(sorted(a for a in w.agents if a not in busy), 14):
        start = DEMO_DAY - timedelta(days=rng.randint(3, 28))
        end = start + timedelta(days=rng.randint(1, 4))
        w.agents[aid].setdefault("leave_days", []).extend(str(start + timedelta(days=i)) for i in range((end - start).days + 1))
        mgr = w.agents[aid]["manager_id"]
        w.add_ctx("leave", "LV", 300, aid, mgr, ist(start - timedelta(days=5), 11),
                  {"employee": aid, "from": str(start), "to": str(end), "approved_by": mgr}, days=(str(start), str(end)))
    for _ in range(4):
        a, b = rng.sample(sorted(a for a in w.agents if a not in busy), 2)
        eff = DEMO_DAY - timedelta(days=rng.randint(10, 25))
        mgr = MANAGER[w.agents[a]["branch"]]
        w.add_ctx("transfer", "TR", 50, a, mgr, ist(eff - timedelta(days=2), 15),
                  {"from_agent": a, "to_agent": b, "approved_by": mgr}, named=b,
                  days=(str(eff), str(eff + timedelta(days=5))))
    bodies = ["Customer requested a callback about renewal premium.", "Address change request received at branch.",
              "Nominee update documents pending from customer.", "Customer asked for a duplicate policy copy.",
              "Follow up on NCB certificate for motor renewal.", "Customer complaint about claim status, escalated to TPA."]
    for _ in range(40):
        aid = rng.choice(sorted(w.agents))
        author = rng.choice([aid, w.agents[aid]["manager_id"]])
        w.add_ctx("ticket", "TKT", 3000, aid, author,
                  ist(DEMO_DAY - timedelta(days=rng.randint(1, 29)), rng.randint(10, 18)),
                  {"author_role": "agent" if author == aid else "branch_manager", "body": rng.choice(bodies)})


# ==================================================================== history (30 normal days)
def build_history(w: World, days: int = HISTORY_DAYS, actors: list[str] | None = None) -> None:
    rng = random.Random(SEED + 1)
    people = {**w.agents, **w.managers}
    actors = actors or sorted(people)
    # Nobody works on a day covered by a leave record (built before history, including scenario leaves).
    off: set[tuple[str, str]] = set()
    for c in w.context:
        if c["type"] == "leave":
            d0, d1 = date.fromisoformat(c["payload"]["from"]), date.fromisoformat(c["payload"]["to"])
            off |= {(c["payload"]["employee"], str(d0 + timedelta(days=i))) for i in range((d1 - d0).days + 1)}
    seq = 0
    for d_back in range(days, 0, -1):
        day = DEMO_DAY - timedelta(days=d_back)
        if day.weekday() == 6:  # Sundays off
            continue
        for aid in actors:
            p = people[aid]
            if (aid, str(day)) in off:
                continue
            if aid == "AG-0577" and day >= DEMO_DAY - timedelta(days=1):
                continue
            n = max(3, int(rng.gauss(p["daily"], p["daily"] * 0.18)))
            device = rng.choice(p["known_devices"])
            session = f"s-{rng.getrandbits(24):06x}"
            start = ist(day, 10, rng.randint(0, 40))
            span = 8 * 3600
            seq += 1
            w.history.append(event(f"ev-h-{seq:07d}", start, aid, "agent", "login", "session", session, None, 0,
                                   p, device, session))
            for t in sorted(rng.randint(60, span) for _ in range(n)):
                seq += 1
                ph = rng.choice(w.portfolios[aid])
                w.history.append(event(f"ev-h-{seq:07d}", start + timedelta(seconds=t), aid, "agent", "view",
                                       "policyholder", ph, w.tier(ph), 1, p, device, session))
    # Partner keys: assigned claims in business hours from the known IP.
    for pk in w.partner_keys:
        for d_back in range(days, 0, -1):
            day = DEMO_DAY - timedelta(days=d_back)
            for t in sorted(rng.randint(0, 9 * 3600) for _ in range(rng.randint(60, 140))):
                seq += 1
                cid = rng.choice(pk["assigned_claims"])
                w.history.append(partner_event(f"ev-h-{seq:07d}", ist(day, 9) + timedelta(seconds=t), pk["key_id"], cid,
                                               "allowed", pk["known_ips"][0], "IN", "Mumbai",
                                               w.claims[cid]["policyholder_id"]))
    w.history.sort(key=lambda e: (e["ts"], e["event_id"]))


def event(eid: str, ts: datetime, actor: str, actor_type: str, action: str, rtype: str, rid: str | None,
          tier: str | None, records: int, p: dict[str, Any], device: str, session: str, *, ip: str | None = None,
          city: str | None = None, country: str = "IN", outcome: str = "allowed", channel: str = "portal",
          detail: dict[str, Any] | None = None) -> dict[str, Any]:
    e = {"event_id": eid, "ts": iso(ts), "actor_id": actor, "actor_type": actor_type, "action": action,
         "resource_type": rtype, "resource_id": rid, "policyholder_id": rid if rtype == "policyholder" else None,
         "tier": tier or "T3", "records": records, "outcome": outcome,
         "channel": channel, "ip": ip or p["home_ip"], "device": device, "city": city or p["city"], "country": country,
         "session_id": session}
    if detail:
        e["detail"] = detail
    return e


def partner_event(eid: str, ts: datetime, key: str, cid: str, outcome: str, ip: str, country: str, city: str,
                  policyholder_id: str | None = None) -> dict:
    return {"event_id": eid, "ts": iso(ts), "actor_id": key, "actor_type": "partner_key", "action": "api_get",
            "resource_type": "claim", "resource_id": cid, "policyholder_id": policyholder_id, "tier": "T1",
            "records": 1 if outcome == "allowed" else 0,
            "outcome": outcome, "channel": "api", "ip": ip, "device": None, "city": city, "country": country,
            "session_id": None}


# ==================================================================== scenarios
class Scn:
    def __init__(self, w: World, sid: str, actor: str, start: datetime, is_attack: bool, meta: dict[str, Any]):
        self.w, self.sid, self.actor, self.start, self.is_attack = w, sid, actor, start, is_attack
        self.p = {**w.agents, **w.managers}.get(actor)
        self.events: list[dict[str, Any]] = []
        self.meta = meta

    def add(self, e: dict[str, Any]) -> None:
        e["event_id"] = f"ev-{self.sid.lower()}-{len(self.events) + 1:05d}"
        e["offset_s"] = int((datetime.fromisoformat(e["ts"]) - self.start).total_seconds())
        e["labels"] = {"scenario": self.sid, "is_attack": self.is_attack}
        self.events.append(e)

    def views(self, targets: list[str], t0: datetime, seconds: int, device: str, session: str, **kw) -> datetime:
        step = seconds / max(1, len(targets))
        for i, ph in enumerate(targets):
            ts = t0 + timedelta(seconds=int(i * step))
            self.add(event("", ts, self.actor, "agent", "view", "policyholder", ph, self.w.tier(ph), 1, self.p, device,
                           session, **kw))
        return t0 + timedelta(seconds=seconds)

    def done(self) -> None:
        self.w.scenarios[self.sid] = self.events
        self.w.manifest[self.sid] = {**self.meta, "actor": self.actor, "is_attack": self.is_attack,
                                     "start": self.events[0]["ts"], "end": self.events[-1]["ts"],
                                     "events": len(self.events),
                                     "records": sum(e["records"] for e in self.events if e["action"] == "view"),
                                     "duration_s": self.events[-1]["offset_s"]}


def s1_bad_night(w: World) -> None:
    rng = random.Random(SEED + 101)
    start = ist(DEMO_DAY, 23, 38)
    s = Scn(w, "S1", "AG-1147", start, True, dict(
        title="An agent's bad night", expected_route="incident", expected_score=89,
        expected_signals=["A1", "A2", "A3", "A4", "A5"], scenario_label="malicious_insider",
        expected_playbooks=["PB1", "PB6", "PB7"]))
    dev, sess, kw = "dv-9f2c", "s-77", dict(ip="100.72.18.24", city="Lucknow")   # new device, new city, off hours
    s.add(event("", start, s.actor, "agent", "login", "session", sess, None, 0, s.p, dev, sess, **kw))
    s.add(event("", start + timedelta(minutes=2), s.actor, "agent", "search", "search", "city=Nagpur product=health",
                None, 0, s.p, dev, sess, detail={"results_listed": 60}, **kw))
    nagpur_health = [p for a, v in w.agents.items() if v["branch"] == "NAGPUR-01" for p in w.portfolios[a]
                     if w.policyholders[p]["product"] == "health"]
    other_health = [p for a, v in w.agents.items() if v["branch"] not in ("NAGPUR-01", "PUNE-02") for p in w.portfolios[a]
                    if w.policyholders[p]["product"] == "health"]
    first = sorted(rng.sample(nagpur_health, 60))
    rest = sorted(rng.sample(sorted(set(nagpur_health + other_health) - set(first)), 1780))
    t = s.views(first, start + timedelta(minutes=2, seconds=30), 4 * 60, dev, sess, **kw)       # 23:40-23:44 -> ~65
    t = s.views(rest, t + timedelta(seconds=20), 31 * 60, dev, sess, **kw)                       # to 1,840 by 00:15
    s.add(event("", ist(DEMO_DAY, 23, 38) + timedelta(minutes=38), s.actor, "agent", "export", "export_file", "EXP-S1-0001",
                "T1", 1200, s.p, dev, sess, detail={"rows": 1200, "format": "csv",
                "fields": ["policyholder_id", "name", "diagnosis", "claim_amount", "hospital"]}, **kw))  # 00:16 -> ~89
    s.done()


def cover_case(w: World, sid: str, subject: str, colleague: str, n: int, start: datetime, genuine: bool,
               label: str, expected_score: int | None, title: str) -> None:
    rng = random.Random(f"{SEED}-{sid}")
    s = Scn(w, sid, subject, start, not genuine, dict(
        title=title, expected_route="auto_resolve" if genuine else "incident", expected_score=expected_score,
        expected_signals=["A1", "A2"], expected_verdict="justified" if genuine else "inconclusive",
        colleague=colleague, scenario_label="benign_exception" if genuine else label))
    dev, sess = s.p["known_devices"][0], f"s-{sid.lower()}"
    s.add(event("", start, subject, "agent", "login", "session", sess, None, 0, s.p, dev, sess))
    targets = sorted(rng.sample(w.t2_of(colleague), n))
    s.views(targets, start + timedelta(minutes=1), 58 * 60, dev, sess)
    s.done()


def s2_tpa_key(w: World) -> None:
    start = ist(DEMO_DAY, 3, 10)
    s = Scn(w, "S2", "PK-CARELINK", start, True, dict(
        title="The TPA key from a new country", expected_route="incident", expected_score=95,
        expected_signals=["P1", "P2", "P3"], scenario_label="compromised_partner", expected_playbooks=["PB2", "PB6", "PB7"]))
    nums = sorted(int(c[3:]) for c in w.claims)
    num, hits, i = nums[len(nums) // 3], 0, 0
    while hits < 420:
        cid = f"CL-{num}"
        claim = w.claims.get(cid)
        outcome = "allowed" if claim else "not_found"
        if claim and claim["tpa_key"] != "PK-CARELINK":
            hits += 1
        s.add(partner_event("", start + timedelta(seconds=int(i * 1.3)), "PK-CARELINK", cid, outcome,
                            "198.51.100.77", "RO", "Bucharest", claim["policyholder_id"] if claim else None))
        num, i = num + 1, i + 1
    s.done()
    s.w.manifest["S2"]["not_found_share"] = round(sum(e["outcome"] == "not_found" for e in s.events) / len(s.events), 2)
    s.w.manifest["S2"]["unassigned_returned"] = hits


def s5_ex_employee(w: World) -> None:
    rng = random.Random(SEED + 105)
    start = ist(DEMO_DAY, 11, 5)
    s = Scn(w, "S5", "AG-0577", start, True, dict(
        title="The ex-employee", expected_route="incident", expected_score=60, expected_formula_score=50,
        expected_signals=["I1"], scenario_label="compromised_account", expected_playbooks=["PB1", "PB7"]))
    dev, sess = s.p["known_devices"][0], "s-s5"
    s.add(event("", start, s.actor, "agent", "login", "session", sess, None, 0, s.p, dev, sess))
    s.views(sorted(rng.sample(w.t2_of("AG-0577"), 40)), start + timedelta(minutes=1), 25 * 60, dev, sess)
    s.done()


def decoys(w: World) -> None:
    rng = random.Random(SEED + 200)
    # D1: manager reviews 300 of the team's T2 records in an hour.
    s = Scn(w, "D1", "MG-014", ist(DEMO_DAY, 15, 0), False, dict(
        title="Branch manager reviewing own team", expected_route="medium_no_incident", expected_score=41,
        expected_signals=["A2"], scenario_label="benign_exception"))
    dev, sess = s.p["known_devices"][0], "s-d1"
    s.add(event("", s.start, s.actor, "agent", "login", "session", sess, None, 0, s.p, dev, sess))
    team_t2 = [p for p in w.portfolios["MG-014"] if w.tier(p) == "T2"]
    s.views(sorted(rng.sample(team_t2, 300)), s.start + timedelta(minutes=1), 58 * 60, dev, sess)
    s.done()
    # D2: servicing assignment cover.
    s = Scn(w, "D2", "AG-1055", ist(DEMO_DAY, 12, 0), False, dict(
        title="Cover under a servicing assignment", expected_route="logged", expected_score=None,
        expected_signals=[], scenario_label="benign_exception"))
    dev, sess = s.p["known_devices"][0], "s-d2"
    s.add(event("", s.start, s.actor, "agent", "login", "session", sess, None, 0, s.p, dev, sess))
    s.views(w.portfolios["AG-1056"][:40], s.start + timedelta(minutes=1), 50 * 60, dev, sess)
    s.done()
    # D3: renewal-campaign spike on own portfolio under approval AP-12.
    s = Scn(w, "D3", "AG-1012", ist(DEMO_DAY, 16, 0), False, dict(
        title="Month-end renewal campaign", expected_route="logged", expected_score=39,
        expected_signals=["A2"], scenario_label="benign_exception"))
    dev, sess = s.p["known_devices"][0], "s-d3"
    s.add(event("", s.start, s.actor, "agent", "login", "session", sess, None, 0, s.p, dev, sess))
    s.views(sorted(rng.sample(w.t2_of("AG-1012"), 150)), s.start + timedelta(minutes=1), 58 * 60, dev, sess)
    s.done()
    # D4: CareLink's approved night batch, known IP, assigned claims only.
    s = Scn(w, "D4", "PK-CARELINK", ist(DEMO_DAY, 2, 0), False, dict(
        title="TPA approved night batch", expected_route="logged", expected_score=None, expected_signals=[],
        scenario_label="benign_exception"))
    carelink = next(k for k in w.partner_keys if k["key_id"] == "PK-CARELINK")
    for i, cid in enumerate(sorted(rng.sample(carelink["assigned_claims"], 120))):
        s.add(partner_event("", s.start + timedelta(seconds=i * 20), "PK-CARELINK", cid, "allowed", "203.0.113.10",
                            "IN", "Mumbai", w.claims[cid]["policyholder_id"]))
    s.done()


def eval_covers(w: World) -> None:
    """Golden-set cover cases: 8 genuine (leave + manager ticket), 5 forged (own ticket; 2 of them on real leave)."""
    rng = random.Random(SEED + 300)
    used = set(NAMED)
    by_branch: dict[str, list[str]] = {}
    for a, v in w.agents.items():
        if a not in used and "leave_days" not in v and len(w.t2_of(a)) >= 60:   # colleague needs enough T2 customers
            by_branch.setdefault(v["branch"], []).append(a)
    pairs = []
    for b in sorted(by_branch):
        group = by_branch[b]
        rng.shuffle(group)
        pairs += [(group[i], group[i + 1], b) for i in range(0, len(group) - 1, 2)]
    pairs = pairs[:13]
    for i, (subject, colleague, branch) in enumerate(pairs):
        genuine = i < 8
        sid = f"EG{i + 1}" if genuine else f"EF{i - 7}"
        mgr = MANAGER[branch]
        on_leave = genuine or i >= 11
        if on_leave:
            w.add_ctx("leave", "LV", 400, colleague, mgr, ist(date(2026, 11, 13), 12),
                      {"employee": colleague, "from": "2026-11-18", "to": "2026-11-24", "approved_by": mgr},
                      days=("2026-11-18", "2026-11-24"))
        author = mgr if genuine else subject
        cname, sname = w.agents[colleague]["name"].split()[0], w.agents[subject]["name"].split()[0]
        body = (f"{sname} to cover {cname}'s customers while {cname} is on leave. Please action." if genuine
                else f"Covering {cname}'s customers this week, approved.")
        w.add_ctx("ticket", "TKT", 5000, colleague, author, ist(date(2026, 11, 17), 15),
                  {"author_role": "branch_manager" if genuine else "agent", "body": body}, named=subject)
        # Volume rule of the proof check: a cover must not read more than the owner's own p95 daily records. The owner's
        # daily volume is ~N(daily, 0.18 daily), so p95 is about 1.3x daily; 0.8x daily keeps a clear margin. At least 12
        # distinct policyholders, so A1 (10 out-of-scope) fires and the case reaches the AI.
        cover_n = max(12, int(0.8 * w.agents[colleague]["daily"]))
        cover_case(w, sid, subject, colleague, cover_n, ist(DEMO_DAY, 10 + i % 6, 5), genuine,
                   "malicious_insider", None, "Golden set: " + ("genuine cover" if genuine else "forged ticket"))


def build_scenarios(w: World, full: bool) -> None:
    s1_bad_night(w)
    cover_case(w, "S1b", "AG-1033", "AG-0932", 130, ist(DEMO_DAY, 10, 30), True, "benign_exception", 54,
               "Cover for a colleague on leave")
    cover_case(w, "S1c", "AG-1088", "AG-1090", 130, ist(DEMO_DAY, 10, 0), False, "malicious_insider", 54,
               "The forged ticket")
    cover_case(w, "S1d", "AG-1120", "AG-1121", 170, ist(DEMO_DAY, 11, 0), False, "malicious_insider", 55,
               "Forged ticket on a real leave")
    s5_ex_employee(w)
    if full:
        s2_tpa_key(w)
        decoys(w)
        eval_covers(w)


# ==================================================================== output
def write(w: World, out: Path, actors: list[str] | None, scenarios: list[str] | None) -> dict[str, int]:
    out.mkdir(parents=True, exist_ok=True)
    (out / "scenarios").mkdir(exist_ok=True)
    keep_agents = set(actors) if actors else None
    if keep_agents:
        keep_agents |= {w.agents[a]["manager_id"] for a in actors if a in w.agents}
    scen = {k: v for k, v in w.scenarios.items() if not scenarios or k in scenarios}

    agents = [a for k, a in w.agents.items() if not keep_agents or k in keep_agents]
    managers = [m for k, m in w.managers.items() if not keep_agents or k in keep_agents]
    portfolios = [{"agent_id": a, "policyholder_id": p} for a, ps in w.portfolios.items()
                  if (not keep_agents or a in keep_agents) and a in w.agents for p in ps]
    agent_phs = {r["policyholder_id"] for r in portfolios}
    # Managers' portfolio = their team's (so reviewing the team is not out of portfolio). In the fixture, only the
    # fixture agents' customers, to keep it small.
    portfolios += [{"agent_id": m, "policyholder_id": p} for m in w.managers if not keep_agents or m in keep_agents
                   for p in w.portfolios[m] if not keep_agents or p in agent_phs]
    touched = {e["resource_id"] for es in scen.values() for e in es if e["resource_type"] == "policyholder"}
    ph_ids = {r["policyholder_id"] for r in portfolios} | touched
    policyholders = [w.policyholders[p] for p in sorted(ph_ids)]
    context = [c for c in w.context if not keep_agents or c["subject_agent"] in keep_agents
               or c["named_agent"] in keep_agents or c["created_by"] in keep_agents]
    claims = [c for c in w.claims.values() if c["policyholder_id"] in ph_ids]
    pks = w.partner_keys if not keep_agents else [{**k, "assigned_claims": [c for c in k["assigned_claims"]
                                                                            if w.claims[c]["policyholder_id"] in ph_ids]}
                                                  for k in w.partner_keys]

    def dump(name: str, rows: Any) -> None:
        (out / name).write_text(json.dumps(rows, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    def dump_lines(name: str, rows: list[dict]) -> None:
        with open(out / name, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")

    def agent_row(a: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in a.items() if k not in ("city", "usual_hours_ist", "leave_days")}
        out.update(home_city=a["city"], usual_start_hour=a["usual_hours_ist"][0], usual_end_hour=a["usual_hours_ist"][1])
        return out

    dump("agents.json", [agent_row(a) for a in agents + managers])
    dump("partner_keys.json", pks)
    dump_lines("policyholders.jsonl", policyholders)
    dump_lines("portfolios.jsonl", portfolios)
    dump_lines("claims.jsonl", claims)
    dump("context_records.json", context)
    dump_lines("history.jsonl", w.history)
    for sid, events in scen.items():
        dump_lines(f"scenarios/{sid}.jsonl", events)
    counts = {"agents": len(agents), "managers": len(managers), "policyholders": len(policyholders),
              "portfolio_rows": len(portfolios), "claims": len(claims), "partner_keys": len(pks),
              "context_records": len(context), "history_events": len(w.history),
              "scenario_events": sum(len(v) for v in scen.values())}
    dump("manifest.json", {"seed": SEED, "demo_day": str(DEMO_DAY), "timestamps": "plain UTC, no timezone",
                           "counts": counts, "scenarios": {k: w.manifest[k] for k in scen}})
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the PolicyGuard synthetic world and scenarios.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--out", type=Path, help="full world (50,000 policyholders, 30 days of history)")
    g.add_argument("--fixture", type=Path, help="small fixture: scenario actors only, 7 days of history")
    args = ap.parse_args()
    w = build_world()
    if args.fixture:
        build_scenarios(w, full=False)
        build_history(w, days=7, actors=FIXTURE_ACTORS)
        w.history = [e for e in w.history if e["actor_type"] == "agent"]   # no partner history in the fixture
        counts = write(w, args.fixture, FIXTURE_ACTORS, FIXTURE_SCENARIOS)
        target = args.fixture
    else:
        build_scenarios(w, full=True)   # first: scenario leaves must be in context before history skips leave days
        build_history(w)
        counts = write(w, args.out, None, None)
        target = args.out
    print(f"wrote {target}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
