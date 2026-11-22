from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ folder, derived from this file so no machine-specific path is stored.
BACKEND_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"
    cors_origins: str = "http://localhost:5173"

    # Placeholder password on purpose: the real DATABASE_URL comes from .env (see .env.example).
    database_url: str = "postgresql+psycopg://compineu:POSTGRES_PASSWORD@localhost:5432/compineu"

    # LLM provider for app/services/llm.py: "groq" or "bedrock". Model names (below) are IDs for that provider.
    llm_provider: str = "groq"
    groq_api_key: str = ""
    bedrock_api_key: str = ""
    bedrock_region: str = "ap-south-1"   # Bedrock client only (llm.py). Everything else uses aws_region below.
    llm_model_heavy: str = ""
    llm_model_light: str = ""

    pii_encryption_key: str = ""

    jwt_secret_key: str = "dev-only-change-me-to-32-random-bytes"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    triage_threshold: float = 0.40
    # XGBoost triage (plan.md section 24). "rules" keeps the rule score; "xgb" reads triage_scores for
    # TRIAGE_MODEL_RUN and opens a case when that score reaches TRIAGE_SCORE_THRESHOLD.
    triage_model: str = "rules"
    triage_model_run: str = ""
    triage_score_threshold: float = 0.6
    # Most model alerts (per edge) grouped per account. The highest-scoring ones are kept.
    model_alerts_per_account: int = 20

    # Paths default to the current locations under BACKEND_ROOT. Override with env vars.
    # Planned move (plan.md section 22): data -> backend/data, checkpoints -> backend/artifacts/models.
    mgnn_dir: Path = BACKEND_ROOT / "external" / "Multi-GNN"
    mgnn_data_dir: Path = BACKEND_ROOT / "external" / "data"
    model_dir: Path = BACKEND_ROOT / "models"
    eval_dir: Path = BACKEND_ROOT / "docs" / "eval"
    raw_csv: Path = BACKEND_ROOT / "docs" / "HI-Small_Trans.csv"

    # Model run (app/pipeline). The old checkpoint: hidden 66, 2 layers.
    model_ckpt: Path = BACKEND_ROOT / "models" / "checkpoint_gin_small.tar"
    model_run_id: str = "model_h66"
    model_hidden: int = 66
    model_layers: int = 2
    model_neighbors: str = "10,10"
    model_chunk_size: int = 250_000
    model_batch_size: int = 4096
    alert_threshold: float = 0.40

    # Region for S3 (PB6 evidence) and CloudWatch Logs (observability page). Set AWS_REGION on the box. Unset falls back
    # to bedrock_region (the old name for the same thing), so existing .env files keep working. See aws_region().
    aws_region: str | None = None

    # CloudWatch Logs group the API writes to (awslogs driver). The admin observability page reads it; unset means
    # the page reports that observability is not configured. observability_region overrides aws_region for logs only.
    observability_log_group: str | None = None
    observability_region: str | None = None

    # PB6 "preserve evidence": S3 bucket with Object Lock (infra/compineu.yaml). Empty disables PB6 with a clear error.
    # Retention is COMPLIANCE mode: 1 day in the organisers' account, 365 in production.
    evidence_bucket: str = ""
    evidence_retention_days: int = 1

    # Mock portal and partner API store: "db" (PolicyGuard tables, migration 0011) or "fixture:<dir>" to serve the
    # generator's files from memory before the tables exist (local development only).
    portal_store: str = "db"

    # Where a case run executes (plan: AgentCore for case runs, phase 2). "local" runs the LangGraph workflow in this
    # process (development and fallback). "agentcore" invokes the AgentCore Runtime agent at agentcore_runtime_arn.
    case_runner: str = "local"
    agentcore_runtime_arn: str = ""
    agentcore_region: str | None = None  # defaults to aws_region

    # Disabled: Celery and Redis are commented out (see app/tasks/__init__.py).
    # redis_url: str = "redis://localhost:6379/0"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def check_production(self) -> None:
        """With APP_ENV=prod, refuse to start on the development defaults (see plan section 23)."""
        if self.app_env != "prod":
            return
        if self.jwt_secret_key.startswith("dev-only") or len(self.jwt_secret_key) < 32:
            raise ValueError("APP_ENV=prod needs JWT_SECRET_KEY of 32+ characters, not the dev default")

    def check_triage(self) -> None:
        """XGBoost triage reads scores for TRIAGE_MODEL_RUN. Without a run every case would fall back to rules."""
        if self.triage_model not in ("rules", "xgb"):
            raise ValueError(f"TRIAGE_MODEL must be rules or xgb, not {self.triage_model!r}")
        if self.triage_model == "xgb" and not self.triage_model_run:
            raise ValueError("TRIAGE_MODEL=xgb needs TRIAGE_MODEL_RUN (the model_version whose scores cases read)")


    def check_case_runner(self) -> None:
        """CASE_RUNNER=agentcore needs the runtime ARN. Without it every case run would fail at the first call."""
        if self.case_runner not in ("local", "agentcore"):
            raise ValueError(f"CASE_RUNNER must be local or agentcore, not {self.case_runner!r}")
        if self.case_runner == "agentcore" and not self.agentcore_runtime_arn:
            raise ValueError("CASE_RUNNER=agentcore needs AGENTCORE_RUNTIME_ARN")


def aws_region(settings: Any) -> str:
    """Region for S3 and CloudWatch: AWS_REGION, else the old BEDROCK_REGION. Reads attributes with getattr so a test
    stub that only has bedrock_region still works."""
    return getattr(settings, "aws_region", None) or getattr(settings, "bedrock_region", None) or "ap-south-1"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.check_production()
    settings.check_triage()
    settings.check_case_runner()
    return settings
