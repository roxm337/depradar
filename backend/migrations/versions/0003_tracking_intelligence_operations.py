"""Preserve inventory identity, threat context, and delivery/worker health.

Revision ID: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "project",
        sa.Column("notifications_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column("project", sa.Column("alert_min_severity", sa.String(20), nullable=True))

    op.add_column(
        "inventory", sa.Column("target_path", sa.String(512), nullable=False, server_default="")
    )
    op.add_column("inventory", sa.Column("revision", sa.String(200), nullable=True))
    op.execute("UPDATE inventory SET target_path = filename WHERE target_path = ''")

    op.add_column(
        "finding", sa.Column("target_path", sa.String(512), nullable=False, server_default="")
    )
    op.add_column("finding", sa.Column("revision", sa.String(200), nullable=True))
    op.add_column("finding", sa.Column("purl", sa.Text(), nullable=True))
    op.add_column(
        "finding",
        sa.Column("cvss_vectors", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column("finding", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("finding", sa.Column("epss_percentile", sa.Float(), nullable=True))
    op.add_column(
        "finding", sa.Column("kev_known", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column(
        "finding", sa.Column("intel_updated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.execute("UPDATE finding SET target_path = target_filename WHERE target_path = ''")

    op.add_column(
        "notification_policy", sa.Column("quiet_hours_start", sa.Integer(), nullable=True)
    )
    op.add_column("notification_policy", sa.Column("quiet_hours_end", sa.Integer(), nullable=True))

    op.add_column(
        "system_state",
        sa.Column("last_worker_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "system_state",
        sa.Column("last_scanner_check_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("system_state", sa.Column("scanner_available", sa.Boolean(), nullable=True))
    op.add_column(
        "system_state",
        sa.Column("last_intelligence_refresh_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "system_state",
        sa.Column("next_intelligence_refresh_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "threat_intel",
        sa.Column("cve_id", sa.String(40), primary_key=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev_known", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "delivery_attempt",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "delivery_id",
            sa.String(36),
            sa.ForeignKey("delivery.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(200), nullable=True),
        sa.Column("provider_id", sa.String(200), nullable=True),
        sa.UniqueConstraint("delivery_id", "attempt_number"),
    )
    op.create_index("ix_delivery_attempt_delivery_id", "delivery_attempt", ["delivery_id"])


def downgrade() -> None:
    op.drop_table("threat_intel")
    op.drop_index("ix_delivery_attempt_delivery_id", table_name="delivery_attempt")
    op.drop_table("delivery_attempt")
    for column in (
        "next_intelligence_refresh_at",
        "last_intelligence_refresh_at",
        "scanner_available",
        "last_scanner_check_at",
        "last_worker_heartbeat_at",
    ):
        op.drop_column("system_state", column)
    op.drop_column("notification_policy", "quiet_hours_end")
    op.drop_column("notification_policy", "quiet_hours_start")
    for column in (
        "intel_updated_at",
        "kev_known",
        "epss_percentile",
        "epss_score",
        "cvss_vectors",
        "purl",
        "revision",
        "target_path",
    ):
        op.drop_column("finding", column)
    op.drop_column("inventory", "revision")
    op.drop_column("inventory", "target_path")
    op.drop_column("project", "alert_min_severity")
    op.drop_column("project", "notifications_enabled")
