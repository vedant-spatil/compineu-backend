"""S3 evidence and CloudWatch read AWS_REGION, falling back to the old BEDROCK_REGION name."""

from types import SimpleNamespace

from app.config import Settings, aws_region
from app.services import evidence, observability


def test_aws_region_wins_over_bedrock_region() -> None:
    s = Settings(_env_file=None, aws_region="eu-west-1", bedrock_region="ap-south-1")
    assert aws_region(s) == "eu-west-1"


def test_falls_back_to_bedrock_region_for_old_env_files() -> None:
    s = Settings(_env_file=None, bedrock_region="us-east-1")
    assert s.aws_region is None
    assert aws_region(s) == "us-east-1"


def test_a_stub_with_only_bedrock_region_still_works() -> None:
    assert aws_region(SimpleNamespace(bedrock_region="ap-south-2")) == "ap-south-2"


def test_aws_region_env_var_is_read(monkeypatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    assert aws_region(Settings(_env_file=None)) == "ap-southeast-1"


def test_evidence_client_uses_aws_region(monkeypatch) -> None:
    seen: dict = {}
    monkeypatch.setattr(evidence, "_client", None)
    monkeypatch.setattr(evidence, "get_settings", lambda: SimpleNamespace(aws_region="eu-west-1", bedrock_region="x"))
    monkeypatch.setattr(evidence.boto3, "client", lambda service, **kw: seen.update(service=service, **kw) or object())
    evidence._s3()
    assert seen == {"service": "s3", "region_name": "eu-west-1"}
    monkeypatch.setattr(evidence, "_client", None)


def test_observability_region_override_beats_aws_region(monkeypatch) -> None:
    seen: dict = {}
    settings = SimpleNamespace(observability_log_group="/compineu/prod", observability_region="us-east-2",
                               aws_region="eu-west-1", bedrock_region="x")
    monkeypatch.setattr(observability, "get_settings", lambda: settings)
    monkeypatch.setattr(observability, "_cache", {})
    monkeypatch.setattr(observability.boto3, "client", lambda service, **kw: seen.update(service=service, **kw) or object())
    monkeypatch.setattr(observability, "_run_queries", lambda *a, **k: {})
    monkeypatch.setattr(observability, "build_summary", lambda raw, hours: {"enabled": True})
    observability.summary(observability.WINDOWS_H[0])
    assert seen == {"service": "logs", "region_name": "us-east-2"}
