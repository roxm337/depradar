"""Add scoped CI/CD API tokens and check-only scans.

Revision ID: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "inventory", sa.Column("kind", sa.String(20), nullable=False, server_default="monitor")
    )
    op.add_column(
        "scan", sa.Column("mode", sa.String(20), nullable=False, server_default="monitor")
    )
    op.add_column("scan", sa.Column("results", sa.JSON(), nullable=True))

    op.create_table(
        "api_token",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("display_prefix", sa.String(24), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("project.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_token_project_id", "api_token", ["project_id"])


def downgrade() -> None:
    # Older revisions would treat check-only inventories as monitored state. Their files become
    # orphans that daily housekeeping removes.
    op.execute("DELETE FROM job WHERE scan_id IN (SELECT id FROM scan WHERE mode = 'check')")
    op.execute("DELETE FROM scan WHERE mode = 'check'")
    op.execute("DELETE FROM inventory WHERE kind = 'check'")
    op.drop_index("ix_api_token_project_id", table_name="api_token")
    op.drop_table("api_token")
    op.drop_column("scan", "results")
    op.drop_column("scan", "mode")
    op.drop_column("inventory", "kind")
