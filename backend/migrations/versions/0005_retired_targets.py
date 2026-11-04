"""Let the owner retire a monitored manifest that was renamed or removed.

Revision ID: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inventory", sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("inventory", "retired_at")
