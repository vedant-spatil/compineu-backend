"""PolicyGuard portal fields: policyholder product and city, access event detail and country.

- parties.product (motor | health | life) decides the tier of a record view: health profiles carry diagnoses, so T1.
- parties.city lets the portal search by city (scenario S1 searches health policyholders in Nagpur).
- access_events.detail holds per-event facts that have no column (export fields and query, search result count,
  refusal reason and HTTP status, the generator's event reference). It keeps `labels` for ground truth only.
- access_events.country is the request's country (scenario S2: a TPA key used from abroad, signal P3).

All columns are nullable, so 0011 data stays valid.

Revision ID: 0012_portal_fields
Revises: 0011_policyguard
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_portal_fields"
down_revision: str | None = "0011_policyguard"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("parties", sa.Column("product", sa.String(16), nullable=True))
    op.add_column("parties", sa.Column("city", sa.String(64), nullable=True))
    op.create_index("ix_parties_city_product", "parties", ["city", "product"])
    op.add_column("access_events", sa.Column("detail", sa.JSON(), nullable=True))
    op.add_column("access_events", sa.Column("country", sa.String(2), nullable=True))


def downgrade() -> None:
    op.drop_column("access_events", "country")
    op.drop_column("access_events", "detail")
    op.drop_index("ix_parties_city_product", table_name="parties")
    op.drop_column("parties", "city")
    op.drop_column("parties", "product")
