"""Tokens for AI assistants (MCP), and an audit trail of the calls they make.

Revision ID: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing tokens keep working where they always did: on the REST API.
    op.add_column(
        "api_token", sa.Column("audience", sa.String(10), nullable=False, server_default="api")
    )
    op.add_column(
        "system_state",
        sa.Column("audit_retention_days", sa.Integer(), nullable=False, server_default="90"),
    )
    op.create_table(
        "audit_event",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("token_id", sa.String(36), nullable=True),
        sa.Column("token_name", sa.String(100), nullable=False),
        sa.Column("client_name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("project_id", sa.String(36), nullable=True),
        sa.Column("outcome", sa.String(10), nullable=False),
        sa.Column("detail", sa.String(300), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
    )
    op.create_index("ix_audit_event_created_at", "audit_event", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_event_created_at", table_name="audit_event")
    op.drop_table("audit_event")
    op.drop_column("system_state", "audit_retention_days")
    # Without the audience column an assistant token would become a REST token; revoke by removal.
    op.execute("DELETE FROM api_token WHERE audience = 'mcp'")
    op.drop_column("api_token", "audience")
