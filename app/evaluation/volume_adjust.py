"""A volume-adjusted LOCAL copy of the golden-set cover cases (EG1-EG8, EF1-EF5), for the live golden set.

    python -m app.evaluation.volume_adjust --src data/policyguard --out data/policyguard_adj

Why: in the generated world the covers read 108-158 records while the covered owner's own p95 is 26-58, so the code's volume
check (volume <= the owner's p95) blocks every cover, genuine or forged. That is a data problem, not a gate problem. This
copy keeps each scenario's login/search/export events and only the first N `view` events, N = max(12, floor(owner p95) - 2),
so volume stays under the owner's p95 and the ticket and leave checks decide. The originals are not touched; the copy is
git-ignored (data/) and must never be committed. Needs the full world in the database (owner history is read from it).
"""

import argparse
import json
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE_MD = REPO_ROOT / "docs" / "eval" / "volume_vs_owner_p95.md"
MIN_VIEWS = 12  # A1 needs 10 distinct policyholders; two spare
MARGIN = 2


def views_to_keep(owner_p95: float | None) -> int | None:
    """N = max(12, floor(p95) - 2). None when the owner has no history (nothing to adjust to)."""
    return None if owner_p95 is None else max(MIN_VIEWS, math.floor(owner_p95) - MARGIN)


def trim_events(events: list[dict[str, Any]], n_views: int) -> list[dict[str, Any]]:
    """Every event that is not a policyholder view (login, search, export) plus the first n_views views, in file order."""
    kept: list[dict[str, Any]] = []
    views = 0
    for e in events:
        if e["action"] == "view":
            if views >= n_views:
                continue
            views += 1
        kept.append(e)
    return kept


def _owner_p95(colleague: str, end: str) -> tuple[int, float | None]:
    from app.db.session import SessionLocal
    from app.orchestration import assembly
    from app.services import pg_data

    now = datetime.fromisoformat(end) + timedelta(seconds=1)
    start, _ = assembly.window_bounds(now.isoformat(), 48)
    with SessionLocal() as db:
        totals = pg_data.fetch_daily_record_totals(db, colleague, start - timedelta(days=30), start)
    p95 = pg_data.percentile(list(totals.values()), 0.95)
    return len(totals), None if p95 is None else round(p95, 1)


def build(src: Path, out: Path) -> list[dict[str, Any]]:
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    cases = [s for s in manifest["scenarios"] if s.startswith(("EG", "EF"))]
    (out / "scenarios").mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    adjusted_manifest = {**manifest, "scenarios": {}}
    for sid in cases:
        m = manifest["scenarios"][sid]
        events = [json.loads(line) for line in (src / "scenarios" / f"{sid}.jsonl").read_text(encoding="utf-8").splitlines()
                  if line.strip()]
        days, p95 = _owner_p95(m["colleague"], m["end"])
        n = views_to_keep(p95)
        orig_views = sum(1 for e in events if e["action"] == "view")
        if n is None:
            raise RuntimeError(f"{sid}: the owner {m['colleague']} has no history in the database")
        n = min(n, orig_views)
        kept = trim_events(events, n)
        distinct = len({e["policyholder_id"] for e in kept if e["action"] == "view" and e.get("policyholder_id")})
        if distinct < 10:
            raise RuntimeError(f"{sid}: only {distinct} distinct policyholders after trimming (A1 needs 10)")
        (out / "scenarios" / f"{sid}.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in kept), encoding="utf-8")
        adjusted_manifest["scenarios"][sid] = {**m, "events": len(kept), "records": n,
                                               "volume_adjusted": {"original_views": orig_views, "kept_views": n,
                                                                   "owner_p95": p95}}
        rows.append({"id": sid, "group": "genuine" if sid.startswith("EG") else "forged", "actor": m["actor"],
                     "owner": m["colleague"], "owner_history_days": days, "owner_p95": p95, "cover_as_generated": orig_views,
                     "exceeds_p95_as_generated": orig_views > (p95 or 0), "cover_adjusted": n, "distinct_policyholders": distinct,
                     "exceeds_p95_adjusted": n > (p95 or 0)})
    (out / "manifest.json").write_text(json.dumps(adjusted_manifest, indent=1) + "\n", encoding="utf-8")
    return rows


def write_table(rows: list[dict[str, Any]], path: Path = TABLE_MD) -> None:
    lines = [
        "Golden-set cover volume against the covered owner's own p95 daily records (same query as the corroboration node).",
        "The code blocks a cover whose volume is above that p95, whatever the ticket says.",
        "",
        f"{'case':5}{'kind':9}{'actor':9}{'owner':9}{'days':>5}{'owner p95':>10}{'cover':>7}{'cover/p95':>10}  as generated"
        f"{'':3}{'adjusted copy':>14}",
    ]
    for r in rows:
        ratio = f"{r['cover_as_generated'] / r['owner_p95']:.1f}x" if r["owner_p95"] else "n/a"
        lines.append(f"{r['id']:5}{r['group']:9}{r['actor']:9}{r['owner']:9}{r['owner_history_days']:>5}{r['owner_p95']!s:>10}"
                     f"{r['cover_as_generated']:>7}{ratio:>10}  {'BLOCKED by volume' if r['exceeds_p95_as_generated'] else 'under p95':18}"
                     f"{r['cover_adjusted']:>5} views, {r['distinct_policyholders']} policyholders")
    over = sum(r["exceeds_p95_as_generated"] for r in rows)
    lines += ["", f"{over} of {len(rows)} covers are above the owner's p95 as generated."]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Trim the golden-set covers to the owner's p95 (local copy, never committed).")
    ap.add_argument("--src", type=Path, default=REPO_ROOT / "data" / "policyguard")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "policyguard_adj")
    args = ap.parse_args()
    rows = build(args.src, args.out)
    write_table(rows)
    print(TABLE_MD.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
