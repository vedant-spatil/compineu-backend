"""PolicyGuard: access events, agents, portfolios, partner keys, context records, decision playbooks.

New tables hold the synthetic insurance data the detectors read (plan section 7). Every new timestamp is a naive
DateTime holding UTC, like alerts.ts. access_events.labels holds the ground truth (scenario, is_attack) for the
quality page only; detectors never read it.

One active case per actor now means one case in status open or awaiting_review. The old index (status <> 'superseded')
counted closed and approved cases too, so an agent could never have a second incident. The per-link indexes on
case_alerts and case_accounts are dropped for the same reason: nothing sets `active` to false when a case closes.

Downgrade restores the old indexes. It fails if an actor by then has two cases that are not superseded (for example a
closed incident and a later one), because the old index forbids that.

Revision ID: 0011_policyguard
Revises: 0010_case_members
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_policyguard"
down_revision: str | None = "0010_case_members"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_STATUSES = "status IN ('open', 'awaiting_review')"
UTC_NOW = sa.text("(now() AT TIME ZONE 'utc')")


def upgrade() -> None:
    op.create_table(
        "access_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("actor_type", sa.String(16), nullable=False),  # agent | partner_key
        sa.Column("action", sa.String(16), nullable=False),  # login | search | view | export | api_get
        sa.Column("resource_type", sa.String(32), nullable=False),  # policyholder | claim | export_file
        sa.Column("resource_id", sa.String(64), nullable=False),
        sa.Column("policyholder_id", sa.String(64), nullable=True),
        sa.Column("tier", sa.String(2), nullable=False),  # T1 | T2 | T3
        sa.Column("records", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("outcome", sa.String(16), nullable=False),  # allowed | denied | not_found
        sa.Column("channel", sa.String(16), nullable=False),  # portal | api
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("device", sa.String(64), nullable=True),
        sa.Column("city", sa.String(64), nullable=True),
        sa.Column("session_id", sa.String(64), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.create_index("ix_access_events_actor_id_ts", "access_events", ["actor_id", "ts"])
    op.create_index("ix_access_events_policyholder_id", "access_events", ["policyholder_id"])
    op.create_index("ix_access_events_ts", "access_events", ["ts"])

    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("branch", sa.String(64), nullable=False),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("hr_status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("credential_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("manager_id", sa.String(32), nullable=True),
        sa.Column("usual_start_hour", sa.Integer(), nullable=False),
        sa.Column("usual_end_hour", sa.Integer(), nullable=False),
        sa.Column("home_city", sa.String(64), nullable=False),
        sa.Column("known_devices", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )

    op.create_table(
        "portfolios",
        sa.Column("agent_id", sa.String(32), primary_key=True),
        sa.Column("policyholder_id", sa.String(64), primary_key=True),
    )
    op.create_index("ix_portfolios_policyholder_id", "portfolios", ["policyholder_id"])

    op.create_table(
        "partner_keys",
        sa.Column("key_id", sa.String(32), primary_key=True),
        sa.Column("partner", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("known_ips", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )

    op.create_table(
        "partner_claim_assignments",
        sa.Column("key_id", sa.String(32), primary_key=True),
        sa.Column("claim_id", sa.String(64), primary_key=True),
    )

    op.create_table(
        "context_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        # leave | transfer | servicing_assignment | approval | ticket
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("subject_agent", sa.String(32), nullable=False),
        sa.Column("named_agent", sa.String(32), nullable=True),
        sa.Column("created_by", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=UTC_NOW),
        sa.Column("valid_from", sa.DateTime(), nullable=True),
        sa.Column("valid_to", sa.DateTime(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )

    op.add_column("decisions", sa.Column("playbooks", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))

    op.drop_index("uq_cases_account_active", table_name="cases")
    op.create_index("uq_cases_account_active", "cases", ["account_id"], unique=True,
                    postgresql_where=sa.text(ACTIVE_STATUSES))
    op.drop_index("uq_case_accounts_account_active", table_name="case_accounts")
    op.drop_index("uq_case_alerts_alert_active", table_name="case_alerts")


def downgrade() -> None:
    op.create_index("uq_case_alerts_alert_active", "case_alerts", ["alert_id"], unique=True,
                    postgresql_where=sa.text("active"))
    op.create_index("uq_case_accounts_account_active", "case_accounts", ["account_id"], unique=True,
                    postgresql_where=sa.text("active"))
    op.drop_index("uq_cases_account_active", table_name="cases")
    op.create_index("uq_cases_account_active", "cases", ["account_id"], unique=True,
                    postgresql_where=sa.text("status <> 'superseded'"))

    op.drop_column("decisions", "playbooks")
    op.drop_table("context_records")
    op.drop_table("partner_claim_assignments")
    op.drop_table("partner_keys")
    op.drop_index("ix_portfolios_policyholder_id", table_name="portfolios")
    op.drop_table("portfolios")
    op.drop_table("agents")
    op.drop_index("ix_access_events_ts", table_name="access_events")
    op.drop_index("ix_access_events_policyholder_id", table_name="access_events")
    op.drop_index("ix_access_events_actor_id_ts", table_name="access_events")
    op.drop_table("access_events")
