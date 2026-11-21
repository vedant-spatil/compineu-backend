"""PII handling before any LLM call (plan section 9).

- Party names and DOBs are replaced by stable tokens (PARTY_001, ...). The token map is kept
  Fernet-encrypted in cases.state and never sent to the LLM.
- Presidio scrubs anything left over in free text (emails, phones, other names).
"""

import copy
import json
import re
from collections.abc import Collection, Mapping
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet

from app.config import get_settings

# Indian identifiers. Deterministic regex, so redaction works without spaCy or Presidio.
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
AADHAAR_RE = re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")

# Identifiers the NER model takes for names ("AG-1147", "MG-015", "PH_001", "PH-00001", "dv-9f2c", "TKT-4471", "PK-CARELINK").
# The part of a PERSON hit that lies on one of them is dropped, so ids and tokens survive the scrub; nothing is rewritten or
# restored, so there is no placeholder a real name could ride through on. An id is letters, "-" or "_", then a DIGIT, so a
# name such as "Priya_Joshi1" or "Anne-Marie" is not an id. Other entity types (email, phone, card) are never dropped.
ID_RE = re.compile(r"\b(?:[A-Za-z]{1,12}[-_]\d[A-Za-z0-9-]*|PK-[A-Z][A-Z0-9-]*)\b")
# Words the NER model glues onto an id ("Agent AG-1147"). A leftover of a PERSON hit made only of these is not a name.
_ID_CONTEXT_WORDS = frozenset({"agent", "agents", "manager", "terminated", "former", "ex", "employee", "user", "actor",
                               "account", "partner", "key", "mr", "mrs", "ms", "dr", "the", "by", "of", "from", "to"})


def _fernet() -> Fernet:
    key = get_settings().pii_encryption_key
    if not key:
        raise RuntimeError("PII_ENCRYPTION_KEY not set (see backend/README.md)")
    return Fernet(key.encode())


def encrypt_map(mapping: dict[str, str]) -> str:
    return _fernet().encrypt(json.dumps(mapping).encode()).decode()


def decrypt_map(token: str) -> dict[str, str]:
    return json.loads(_fernet().decrypt(token.encode()).decode())


def tokenize_parties(parties: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Return (redacted party list, token->original map). Names/DOBs removed."""
    mapping: dict[str, str] = {}
    redacted: list[dict[str, Any]] = []
    for i, p in enumerate(parties, start=1):
        token = f"PARTY_{i:03d}"
        mapping[token] = p["name"]
        redacted.append({"party_token": token, "country": p.get("country"), "account_id": p["account_id"]})
    return redacted, mapping


def redact_indian_ids(text: str) -> str:
    """PAN -> [PAN], Aadhaar (12 digits, optionally grouped 4-4-4 with a space or dash) -> [AADHAAR]. Pure."""
    return AADHAAR_RE.sub("[AADHAAR]", PAN_RE.sub("[PAN]", text))


def replace_names(text: str, name_to_token: Mapping[str, str]) -> str:
    """Case-insensitive replacement of each name by its token, longest name first. Pure."""
    for name in sorted(name_to_token, key=len, reverse=True):
        if name:
            text = re.sub(re.escape(name), name_to_token[name], text, flags=re.IGNORECASE)
    return text


def scrub_text(text: str, names: list[str]) -> str:
    """Replace known names, redact PAN and Aadhaar, then run Presidio for residual PII."""
    for name in sorted(names, key=len, reverse=True):
        if name:
            text = re.sub(re.escape(name), "[PARTY]", text, flags=re.IGNORECASE)
    text = redact_indian_ids(text)
    return _presidio().anonymize_text(text)


def scrub_obj(obj: Any, names: list[str], *, skip_keys: Collection[str] = ()) -> Any:
    """scrub_text on every string inside dicts, lists and tuples. Returns a new object and never mutates the input.
    Dict keys are kept. A value under a key in skip_keys is returned unchanged (structured fields such as ids)."""
    if isinstance(obj, str):
        return scrub_text(obj, names) if obj.strip() else obj
    if isinstance(obj, Mapping):
        return {k: (v if k in skip_keys else scrub_obj(v, names, skip_keys=skip_keys)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_obj(v, names, skip_keys=skip_keys) for v in obj]
    return obj


@lru_cache(maxsize=1)
def _presidio():
    return _PresidioScrubber()


class _PresidioScrubber:
    def __init__(self) -> None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str) -> str:
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "PERSON"],
        )
        return self._anonymizer.anonymize(text=text, analyzer_results=exclude_ids(text, results)).text


def exclude_ids(text: str, results: list[Any]) -> list[Any]:
    """Cut every id (ID_RE) out of the PERSON hits. A hit wholly on an id goes. A hit that also covers other words ("Rahul
    Verma AG-1147") keeps those words, so a real name next to an id is still scrubbed. Non-PERSON hits are returned unchanged."""
    spans = [m.span() for m in ID_RE.finditer(text)]
    kept: list[Any] = []
    for r in results:
        if r.entity_type != "PERSON" or not any(r.start < e and s < r.end for s, e in spans):
            kept.append(r)
            continue
        pieces = [(r.start, r.end)]
        for s, e in spans:
            cut: list[tuple[int, int]] = []
            for a, b in pieces:
                if e <= a or s >= b:
                    cut.append((a, b))
                    continue
                cut.extend(p for p in ((a, s), (e, b)) if p[0] < p[1])
            pieces = cut
        for a, b in pieces:
            words = re.findall(r"[^\W\d_]+", text[a:b])
            if not words or all(w.lower() in _ID_CONTEXT_WORDS for w in words):
                continue
            piece = copy.copy(r)
            piece.start = a + len(text[a:b]) - len(text[a:b].lstrip())
            piece.end = b - (len(text[a:b]) - len(text[a:b].rstrip()))
            kept.append(piece)
    return kept
