from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    LargeBinary,
    UniqueConstraint,
    text,
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="investigator")  # admin | qa
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Profile picture: PNG or JPEG, checked by the API. Deferred, so it loads only when it is served.
    avatar: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    avatar_type: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64), index=True)
    amount: Mapped[float] = mapped_column(Numeric(18, 2))
    ts: Mapped[datetime] = mapped_column(DateTime)
    source_label: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[float] = mapped_column(Float)
    rules: Mapped[list[Any]] = mapped_column(JSON, default=list)
    is_laundering: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # "rules" (app/ingest) or "model" (app/ml). model_version is set only for model alerts.
    source: Mapped[str] = mapped_column(String(16), default="rules", server_default="rules", index=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)


class TriageScore(Base):
    """Per account and day score from the XGBoost triage model (plan.md section 24). One set per model_version."""
    __tablename__ = "triage_scores"
    __table_args__ = (Index("ix_triage_scores_account_date", "account_id", "score_date"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64))
    score_date: Mapped[date] = mapped_column(Date)
    score: Mapped[float] = mapped_column(Float)
    reason_codes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    model_version: Mapped[str] = mapped_column(String(64), index=True)


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    from_bank: Mapped[str] = mapped_column(String(32))
    from_account: Mapped[str] = mapped_column(String(64), index=True)
    to_bank: Mapped[str] = mapped_column(String(32))
    to_account: Mapped[str] = mapped_column(String(64), index=True)
    amount_received: Mapped[float] = mapped_column(Numeric(18, 2))
    receiving_currency: Mapped[str] = mapped_column(String(32))
    amount_paid: Mapped[float] = mapped_column(Numeric(18, 2))
    payment_currency: Mapped[str] = mapped_column(String(32))
    payment_format: Mapped[str] = mapped_column(String(32))
    is_laundering: Mapped[bool] = mapped_column(Boolean)
    pattern: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Party(Base):
    __tablename__ = "parties"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    dob: Mapped[str] = mapped_column(String(10))
    country: Mapped[str] = mapped_column(String(2), default="US")
    planted: Mapped[bool] = mapped_column(Boolean, default=False)
    # PolicyGuard (migration 0012): line of business decides the tier of a view (health = T1), city drives search.
    product: Mapped[str | None] = mapped_column(String(16), nullable=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Case(Base):
    __tablename__ = "cases"
    # One active case (open or awaiting_review) per account. Decided and superseded cases are outside the index, so an
    # actor can have a new incident after an earlier one is closed (migration 0011).
    __table_args__ = (Index("uq_cases_account_active", "account_id", unique=True,
                            postgresql_where=text("status IN ('open', 'awaiting_review')")),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    account_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="open")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The QA user this case is assigned to. Admins see every case; QA sees only their own (services/access.py).
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)


class CaseAlert(Base):
    """An alert that belongs to a case. No unique index since migration 0011: the cases index is the guard."""

    __tablename__ = "case_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CaseAccount(Base):
    """An account that belongs to a case. No unique index since migration 0011: the cases index is the guard."""

    __tablename__ = "case_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    account_id: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16), default="subject", server_default="subject")
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Notification(Base):
    """In-app notification for one user. Messages are generic and carry no case content."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(String(300))
    link: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseEvent(Base):
    __tablename__ = "case_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    node: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    action: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    typologies: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Playbook IDs the approver chose (PB1, PB2, PB6, PB7). Empty for close and for approvals without playbooks.
    playbooks: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default=text("'[]'"))
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SarDraft(Base):
    __tablename__ = "sar_drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    body_redacted: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LlmCache(Base):
    __tablename__ = "llm_cache"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    response: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Import(Base):
    """A CSV upload awaiting validation or load. Loads are run by app.ingest.load (see plan)."""

    __tablename__ = "imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    # uploaded -> validating -> rejected | loading -> triaging -> triaged | failed (see app/services/sync.py)
    status: Mapped[str] = mapped_column(String(32), default="uploaded")
    report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Project(Base):
    """A group of accounts reviewed by QA members, managed by admin (plan: projects)."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    auto_validate: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)


class ProjectAccount(Base):
    __tablename__ = "project_accounts"
    __table_args__ = (UniqueConstraint("project_id", "account_id", name="uq_project_account"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    account_id: Mapped[str] = mapped_column(String(64))


class Evaluation(Base):
    """One QA review of one account in a project. Auto drafts come from the worker (source=auto).

    Status flow: draft (auto only) -> submitted (QA) -> accepted | rejected (admin).
    A rejected evaluation goes back to QA, who resubmits (status submitted)."""

    __tablename__ = "evaluations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    account_id: Mapped[str] = mapped_column(String(64), index=True)
    qa_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(8), default="qa")  # auto | qa
    status: Mapped[str] = mapped_column(String(16), default="submitted")  # draft | submitted | accepted | rejected
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reject_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# --- PolicyGuard (migration 0011). Every timestamp below is a naive DateTime holding UTC, like alerts.ts. ---

_UTC_NOW = text("(now() AT TIME ZONE 'utc')")


class AccessEvent(Base):
    """One read, search, export or API call by an agent or a partner key. `labels` is ground truth (scenario,
    is_attack) for the quality page only; detectors must never read it. Evidence IDs (`txn_ids`) are these IDs."""

    __tablename__ = "access_events"
    __table_args__ = (Index("ix_access_events_actor_id_ts", "actor_id", "ts"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    actor_id: Mapped[str] = mapped_column(String(64))
    actor_type: Mapped[str] = mapped_column(String(16))  # agent | partner_key
    action: Mapped[str] = mapped_column(String(16))  # login | search | view | export | api_get
    resource_type: Mapped[str] = mapped_column(String(32))  # policyholder | claim | export_file
    resource_id: Mapped[str] = mapped_column(String(64))
    policyholder_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    tier: Mapped[str] = mapped_column(String(2))  # T1 | T2 | T3
    records: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))
    outcome: Mapped[str] = mapped_column(String(16))  # allowed | denied | not_found
    channel: Mapped[str] = mapped_column(String(16))  # portal | api
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    device: Mapped[str | None] = mapped_column(String(64), nullable=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, server_default=text("'{}'"))
    # Migration 0012: facts without a column (export fields, refusal reason, source event ref) and request country.
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)


class Agent(Base):
    """An insurance agent (synthetic). PB1 sets credential_enabled to false."""

    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    branch: Mapped[str] = mapped_column(String(64))
    channel: Mapped[str] = mapped_column(String(32))
    hr_status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    credential_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    manager_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    usual_start_hour: Mapped[int] = mapped_column(Integer)
    usual_end_hour: Mapped[int] = mapped_column(Integer)
    home_city: Mapped[str] = mapped_column(String(64))
    known_devices: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default=text("'[]'"))


class Portfolio(Base):
    """An agent's own book: which policyholders (parties.account_id, e.g. PH-48213) the agent services."""

    __tablename__ = "portfolios"

    agent_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    policyholder_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)


class PartnerKey(Base):
    """A partner (TPA) API key. PB2 sets enabled to false."""

    __tablename__ = "partner_keys"

    key_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    partner: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    known_ips: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default=text("'[]'"))


class PartnerClaimAssignment(Base):
    """A claim a partner key is allowed to fetch."""

    __tablename__ = "partner_claim_assignments"

    key_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(64), primary_key=True)


class ContextRecord(Base):
    """Business context: leave, transfer, servicing_assignment, approval or ticket. `subject_agent` is whose portfolio
    or leave it is about; `named_agent` is who it authorises. Free text in `payload` is untrusted data."""

    __tablename__ = "context_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    subject_agent: Mapped[str] = mapped_column(String(32))
    named_agent: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=_UTC_NOW)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, server_default=text("'{}'"))
