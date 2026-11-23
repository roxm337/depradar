"""Several Telegram recipients, and a project scope for every notification destination.

Revision ID: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing rows were named after their channel, so their id is also their channel.
    op.add_column("connector", sa.Column("channel", sa.String(20), nullable=True))
    op.execute("UPDATE connector SET channel = id")
    op.alter_column("connector", "channel", nullable=False)
    op.add_column("connector", sa.Column("label", sa.String(80), nullable=False, server_default=""))
    op.add_column(
        "connector",
        sa.Column("all_projects", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "connector",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.add_column("connector", sa.Column("removed_at", sa.DateTime(timezone=True)))
    op.create_table(
        "connector_project",
        sa.Column("connector_id", sa.String(20), sa.ForeignKey("connector.id"), primary_key=True),
        sa.Column(
            "project_id",
            sa.String(36),
            sa.ForeignKey("project.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    # Telegram's update offset belongs to the bot, which every paired chat shares.
    op.add_column(
        "system_state",
        sa.Column("telegram_update_offset", sa.Integer(), nullable=False, server_default="0"),
    )
    op.execute(
        "UPDATE system_state SET telegram_update_offset = COALESCE("
        "(SELECT update_offset FROM connector WHERE id = 'telegram'), 0)"
    )
    op.drop_column("connector", "update_offset")


def downgrade() -> None:
    op.add_column(
        "connector",
        sa.Column("update_offset", sa.Integer(), nullable=False, server_default="0"),
    )
    op.execute(
        "UPDATE connector SET update_offset = "
        "(SELECT telegram_update_offset FROM system_state WHERE id = 1) WHERE id = 'telegram'"
    )
    op.drop_column("system_state", "telegram_update_offset")
    op.drop_table("connector_project")
    # The older schema has one destination per channel; extra recipients cannot be kept.
    extra = "SELECT id FROM connector WHERE id NOT IN ('email', 'telegram')"
    op.execute(
        f"DELETE FROM delivery_attempt WHERE delivery_id IN "
        f"(SELECT id FROM delivery WHERE connector_id IN ({extra}))"
    )
    op.execute(f"DELETE FROM delivery WHERE connector_id IN ({extra})")
    op.execute(f"DELETE FROM connector WHERE id IN ({extra})")
    op.drop_column("connector", "removed_at")
    op.drop_column("connector", "created_at")
    op.drop_column("connector", "all_projects")
    op.drop_column("connector", "label")
    op.drop_column("connector", "channel")
