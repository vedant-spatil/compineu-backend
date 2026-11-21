"""Ids and tokens must survive the Presidio scrub. In the real run the NER model turned "AG-1147" into <PERSON> in the report
title and summary ("Terminated Agent <PERSON> Policyholder Records"). The part of a PERSON hit that lies on an id is now
dropped, a real name next to an id is still scrubbed, and other entity types still go."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from app.config import get_settings
from app.orchestration import assembly
from app.services import pii


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("PII_ENCRYPTION_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _scrubber_with(results):
    """A scrubber whose analyzer returns fixed hits; the real anonymizer then applies them."""
    scrubber = pii._PresidioScrubber.__new__(pii._PresidioScrubber)
    scrubber._analyzer = SimpleNamespace(analyze=lambda **kw: results)
    from presidio_anonymizer import AnonymizerEngine

    scrubber._anonymizer = AnonymizerEngine()
    return scrubber


def _hit(text: str, needle: str, entity: str):
    start = text.index(needle)
    return SimpleNamespace(entity_type=entity, start=start, end=start + len(needle), score=0.9,
                           analysis_explanation=None, recognition_metadata=None)


@pytest.mark.parametrize("needle", ["AG-1147", "Agent AG-1147", "PH_001", "MG-015", "PK-CARELINK"])
def test_a_person_hit_on_an_id_is_dropped(needle):
    text = "Agent AG-1147 read PH_001 after MG-015 signed off for PK-CARELINK."
    out = _scrubber_with([_hit(text, needle, "PERSON")]).anonymize_text(text)
    assert out == text


def test_a_person_hit_on_a_real_name_and_other_entities_still_go():
    text = "Agent AG-1147 spoke to Jane Roe, mail jane.roe-1@example.com."
    out = _scrubber_with([_hit(text, "Jane Roe", "PERSON"), _hit(text, "jane.roe-1@example.com", "EMAIL_ADDRESS")]
                         ).anonymize_text(text)
    assert "AG-1147" in out and "Jane Roe" not in out and "example.com" not in out


def test_a_name_merged_into_an_id_hit_is_still_scrubbed():
    """The NER model can return one PERSON span over a name and the id after it. Only the id is exempt."""
    text = "Rahul Verma AG-1147 opened PH_001."
    out = _scrubber_with([_hit(text, "Rahul Verma AG-1147", "PERSON")]).anonymize_text(text)
    assert "Rahul" not in out and "Verma" not in out and "AG-1147" in out and "PH_001" in out
    text = "Dev AG-1088 and then Raj Mehta MG-014 signed."
    out = _scrubber_with([_hit(text, "Dev AG-1088", "PERSON"), _hit(text, "Raj Mehta MG-014", "PERSON")]).anonymize_text(text)
    assert "AG-1088" in out and "MG-014" in out and "Raj" not in out and "Mehta" not in out and "Dev" not in out


@pytest.mark.parametrize("lookalike", ["Priya_Joshi1", "Anne-Marie", "Rahul Verma-2nd", "PK-lowercase", "PK-"])
def test_a_name_that_only_looks_like_an_id_is_not_exempt(lookalike):
    """An id is letters, '-' or '_', then a digit (or PK- and capitals). Anything else is treated as a name."""
    text = f"Contact {lookalike} today."
    out = _scrubber_with([_hit(text, lookalike, "PERSON")]).anonymize_text(text)
    assert lookalike not in out and "<PERSON>" in out


def test_nothing_is_restored_so_an_id_shaped_name_cannot_carry_a_real_name():
    """Names in the identity map are replaced before Presidio runs, so even an id-shaped wrapper does not keep one."""
    out = pii.scrub_text("Ticket by AG-0932 (Priya Joshi) and PH_001 for Priya Joshi.", ["Priya Joshi"])
    assert "Priya" not in out and "Joshi" not in out and "AG-0932" in out and "PH_001" in out


def test_scrub_text_keeps_ids_and_removes_known_names():
    text = "AG-1147 opened PH_001 for Priya Joshi; ticket TKT-4471."
    out = pii.scrub_text(text, ["Priya Joshi"])
    assert "Priya Joshi" not in out and "AG-1147" in out and "PH_001" in out and "TKT-4471" in out


# ---- real Presidio + spaCy, on the strings of the real run ---------------------------------------------------------

TITLE = "Terminated Agent AG-0577 accessed policyholder records"
SUMMARY = ("Agent AG-0577 (manager MG-014, partner key PK-CARELINK) opened PH_001 and PH_002 from device dv-9f2c after "
           "HR terminated the account. Ticket TKT-4471 and leave LV-221 do not name this agent.")
IDS = ["AG-0577", "MG-014", "PK-CARELINK", "PH_001", "PH_002", "dv-9f2c", "TKT-4471", "LV-221"]


def test_real_presidio_keeps_ids_in_a_title_and_a_summary():
    for text in (TITLE, SUMMARY):
        out = pii.scrub_text(text, ["Sanjay More"])
        assert "<PERSON>" not in out
        assert all(i in out for i in IDS if i in text)
    assert pii.scrub_text(TITLE, []) == TITLE


def test_real_presidio_still_removes_real_names_next_to_ids():
    out = pii.scrub_text("Terminated Agent AG-0577 Sanjay More and Rahul Verma, PAN ABCDE1234F, Aadhaar 1234 5678 9012.",
                         ["Sanjay More"])
    assert "AG-0577" in out and "Sanjay" not in out and "Rahul" not in out and "Verma" not in out
    assert "ABCDE1234F" not in out and "1234 5678 9012" not in out and "[PAN]" in out and "[AADHAAR]" in out


def _all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_strings(v)


def test_every_text_field_of_the_report_keeps_ids_and_loses_names():
    """The report as stored: assembled in code, then scrub_obj with the same skip keys agents.report_writer uses."""
    llm = {
        "title": TITLE,
        "summary": SUMMARY + " Sanjay More's PAN ABCDE1234F and Aadhaar 1234 5678 9012 were in the ticket.",
        "timeline": [{"event_id": 11, "what": "AG-0577 opened PH_001 on dv-9f2c, then Sanjay More's record."}],
        "cert_in_draft": {"summary": "DRAFT - Terminated Agent AG-0577 read PH_001.", "incident_type": "Access by ex-employee AG-0577",
                          "systems_affected": "Portal key PK-CARELINK", "timeline_summary": "AG-0577 on dv-9f2c, approved by MG-014.",
                          "actions_taken": "Suspend AG-0577; ask Rahul Verma to review."},
        "dpdp_intimation_draft": {"nature": "Terminated Agent AG-0577 accessed PH_001.", "extent": "PH_001, PH_002 read.",
                                  "timing": "From dv-9f2c.", "location": "Portal key PK-CARELINK.",
                                  "likely_impact": "AG-0577 had no authority; TKT-4471 does not name AG-0577."},
        "open_questions": ["Was AG-0577 on device dv-9f2c issued by MG-014?", "Who is Sanjay More's line manager?"],
    }
    just = {"verdict": "unjustified", "llm_verdict": "unjustified",
            "reasoning": "No record names AG-0577; TKT-4471 is for AG-1033. Sanjay More left on leave LV-221.",
            "missing_evidence": ["No ticket naming AG-0577 from MG-014"],
            "corroboration": {"ok": False, "failed_checks": ["no_authorising_record"], "reasons": ["No record names AG-0577."]}}
    report = assembly.assemble_report(
        llm, agent_id="AG-0577", evidence={"top_events": [{"event_id": 11, "ts": "2026-11-20T18:08:00Z", "action": "view",
                                                           "records": 1, "outcome": "allowed"}]},
        justification=just, classification={"scenario": "malicious_insider", "cited_event_ids": [11]},
        clocks=assembly.compute_clocks(datetime(2026, 11, 20, 18, 21, 30, tzinfo=timezone.utc)), allowed_ids={11}, failures=[],
        risk_score=0.6)
    out = pii.scrub_obj(report, ["Sanjay More", "Rahul Verma"], skip_keys=assembly.SCRUB_SKIP_KEYS)

    text = "\n".join(_all_strings(out))
    assert "<PERSON>" not in text
    assert "Sanjay" not in text and "Rahul" not in text and "Verma" not in text
    assert "ABCDE1234F" not in text and "1234 5678 9012" not in text
    assert out["title"] == TITLE
    for field, ids in {
        "summary": ["AG-0577", "MG-014", "PK-CARELINK", "PH_001", "PH_002", "dv-9f2c", "TKT-4471", "LV-221"],
    }.items():
        assert all(i in out[field] for i in ids)
    assert "AG-0577" in out["timeline"][0]["what"] and "PH_001" in out["timeline"][0]["what"] and "dv-9f2c" in out["timeline"][0]["what"]
    assert all("AG-0577" in out["cert_in_draft"][k] for k in ("summary", "incident_type", "timeline_summary", "actions_taken"))
    assert "PK-CARELINK" in out["cert_in_draft"]["systems_affected"] and "MG-014" in out["cert_in_draft"]["timeline_summary"]
    assert "AG-0577" in out["dpdp_intimation_draft"]["nature"] and "PH_002" in out["dpdp_intimation_draft"]["extent"]
    assert "dv-9f2c" in out["dpdp_intimation_draft"]["timing"] and "PK-CARELINK" in out["dpdp_intimation_draft"]["location"]
    assert "AG-0577" in out["dpdp_intimation_draft"]["likely_impact"] and "TKT-4471" in out["dpdp_intimation_draft"]["likely_impact"]
    assert "dv-9f2c" in out["open_questions"][0] and "MG-014" in out["open_questions"][0]
    assert "AG-0577" in out["justification"]["reasoning"] and "LV-221" in out["justification"]["reasoning"]
    assert "AG-0577" in out["justification"]["missing_evidence"][0]
    assert out["actor"] == "AG-0577"
