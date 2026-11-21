"""PolicyGuard Risk (plan section 4): likelihood from the signals' confidences, impact from tier and records touched.

Pure functions, no database:

    L    = 1 - prod(1 - c_i)
    I    = W[tier] * min(1, log10(1 + n_records) / 4)        W: T1 1.0, T2 0.5, T3 0.2
    Risk = min(100, 100 * L * (0.4 + 0.6 * I) * p)          p = 1.2 for partner keys, else 1.0
    Risk = max(Risk, 60) if I1 fired

Risk is rounded to one decimal, and the band is taken from that rounded value so the two always agree on screen.
Alert.risk_score stores Risk / 100, so TRIAGE_THRESHOLD=0.40 is the low/medium boundary.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping

TIER_WEIGHT = {"T1": 1.0, "T2": 0.5, "T3": 0.2}
PARTNER_MULTIPLIER = 1.2
I1_FLOOR = 60.0
# Lower bound of each band, highest first. Anything below the last one is "low".
BANDS = ((80.0, "critical"), (60.0, "high"), (40.0, "medium"))


def likelihood(confidences: Iterable[float]) -> float:
    """L = 1 - prod(1 - c): the chance that at least one signal is right, treating them as independent."""
    miss = 1.0
    for c in confidences:
        if not 0.0 <= c <= 1.0:
            raise ValueError(f"signal confidence must be between 0 and 1, got {c}")
        miss *= 1.0 - c
    return 1.0 - miss


def impact(tier: str | None, n_records: int) -> float:
    """I = W[tier] * min(1, log10(1 + n) / 4). An unknown or missing tier weighs 0; 10,000 records saturate."""
    weight = TIER_WEIGHT.get(tier or "", 0.0)
    return weight * min(1.0, math.log10(1 + max(0, n_records)) / 4)


def risk_score(signals: Mapping[str, float], tier: str | None, n_records: int, actor_type: str) -> float:
    """Risk 0..100 for signal id -> confidence. No signals means 0."""
    if not signals:
        return 0.0
    p = PARTNER_MULTIPLIER if actor_type == "partner_key" else 1.0
    value = min(100.0, 100.0 * likelihood(signals.values()) * (0.4 + 0.6 * impact(tier, n_records)) * p)
    if "I1" in signals:
        value = max(value, I1_FLOOR)
    return round(value, 1)


def band(risk: float) -> str:
    """>=80 critical, 60-79 high, 40-59 medium, <40 low."""
    for lower, name in BANDS:
        if risk >= lower:
            return name
    return "low"


def score(signals: Mapping[str, float], tier: str | None, n_records: int, actor_type: str) -> tuple[float, str]:
    """(Risk, band) in one call."""
    value = risk_score(signals, tier, n_records, actor_type)
    return value, band(value)
