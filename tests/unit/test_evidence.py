from types import SimpleNamespace

import pytest

from app.services import evidence


class StubS3:
    def __init__(self, fail: bool = False):
        self.calls: list[dict] = []
        self.fail = fail

    def put_object(self, **kwargs):
        if self.fail:
            raise RuntimeError("AccessDenied")
        self.calls.append(kwargs)
        return {"VersionId": "v1"}


@pytest.fixture
def settings(monkeypatch):
    s = SimpleNamespace(evidence_bucket="pg-evidence", evidence_retention_days=1, bedrock_region="ap-south-1")
    monkeypatch.setattr(evidence, "get_settings", lambda: s)
    audit: list[tuple] = []
    monkeypatch.setattr(evidence, "write_event", lambda db, case_id, node, kind, payload: audit.append((kind, payload)))
    return s, audit


def test_writes_compliance_locked_object_and_audits_receipt(settings) -> None:
    _, audit = settings
    s3 = StubS3()
    receipt = evidence.preserve_evidence(None, 7, {"event_ids": [1, 2]}, approved_by="ana", reason="r" * 20, client=s3)

    call = s3.calls[0]
    assert call["Bucket"] == "pg-evidence"
    assert call["ObjectLockMode"] == "COMPLIANCE"
    assert call["ObjectLockRetainUntilDate"] > call["ObjectLockRetainUntilDate"].replace(year=2000)
    assert call["Key"].startswith("incidents/7/")
    assert receipt["version_id"] == "v1" and receipt["sha256"] == call["Metadata"]["sha256"]
    assert audit == [("PB6_evidence_preserved", receipt)]


def test_refuses_without_bucket(settings) -> None:
    s, audit = settings
    s.evidence_bucket = ""
    with pytest.raises(evidence.EvidenceError, match="EVIDENCE_BUCKET"):
        evidence.preserve_evidence(None, 7, {}, approved_by="ana", reason="x", client=StubS3())
    assert audit == []


def test_s3_failure_is_reported_and_not_audited(settings) -> None:
    _, audit = settings
    with pytest.raises(evidence.EvidenceError, match="S3 refused"):
        evidence.preserve_evidence(None, 7, {}, approved_by="ana", reason="x", client=StubS3(fail=True))
    assert audit == []
