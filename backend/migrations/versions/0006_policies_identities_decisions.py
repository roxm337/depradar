"""Central security policies, trusted CI identities, and recorded gate decisions.

Revision ID: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trusted_identity",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("project.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("issuer", sa.String(300), nullable=False),
        sa.Column("repository", sa.String(300), nullable=False),
        sa.Column("repository_id", sa.String(40), nullable=True),
        sa.Column("workflow", sa.String(300), nullable=True),
        sa.Column("monitor_ref", sa.String(300), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_trusted_identity_project_id", "trusted_identity", ["project_id"])

    op.add_column(
        "api_token", sa.Column("kind", sa.String(20), nullable=False, server_default="static")
    )
    op.add_column(
        "api_token",
        sa.Column(
            "identity_id", sa.String(36), sa.ForeignKey("trusted_identity.id"), nullable=True
        ),
    )
    op.add_column("api_token", sa.Column("claims", sa.JSON(), nullable=True))
    op.create_index("ix_api_token_identity_id", "api_token", ["identity_id"])

    op.create_table(
        "security_policy",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope_key", sa.String(36), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("project.id"), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("rules", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("note", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scope_key", "version"),
    )
    op.create_index("ix_security_policy_project_id", "security_policy", ["project_id"])

    op.create_table(
        "gate_decision",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("project.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("revision", sa.String(200), nullable=True),
        sa.Column("commit", sa.String(64), nullable=True),
        sa.Column("violations", sa.Integer(), nullable=False),
        sa.Column("ignored", sa.Integer(), nullable=False),
        sa.Column("below_threshold", sa.Integer(), nullable=False),
        sa.Column("actor", sa.JSON(), nullable=False),
        sa.Column("inputs", sa.JSON(), nullable=False),
        sa.Column("exceptions", sa.JSON(), nullable=False),
        sa.Column("intelligence_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=False),
    )
    op.create_index("ix_gate_decision_created_at", "gate_decision", ["created_at"])
    op.create_index(
        "ix_gate_decision_project_created", "gate_decision", ["project_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_gate_decision_project_created", table_name="gate_decision")
    op.drop_index("ix_gate_decision_created_at", table_name="gate_decision")
    op.drop_table("gate_decision")
    op.drop_index("ix_security_policy_project_id", table_name="security_policy")
    op.drop_table("security_policy")
    # Exchanged identity tokens cannot exist without their identity; owner tokens are kept.
    op.execute("DELETE FROM api_token WHERE kind = 'identity'")
    op.drop_index("ix_api_token_identity_id", table_name="api_token")
    op.drop_column("api_token", "claims")
    op.drop_column("api_token", "identity_id")
    op.drop_column("api_token", "kind")
    op.drop_index("ix_trusted_identity_project_id", table_name="trusted_identity")
    op.drop_table("trusted_identity")
