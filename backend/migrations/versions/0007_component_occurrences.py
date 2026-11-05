"""Index the packages of monitored manifests so the owner can search where a package is used.

Revision ID: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rows fill as monitored manifests are next scanned; nothing is derived here.
    op.create_table(
        "component_occurrence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("inventory_id", sa.String(36), sa.ForeignKey("inventory.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("project.id"), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scan.id"), nullable=False),
        sa.Column("ecosystem", sa.String(100), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("normalized_name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("purl", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_component_occurrence_inventory_id", "component_occurrence", ["inventory_id"]
    )
    op.create_index("ix_component_occurrence_project_id", "component_occurrence", ["project_id"])
    op.create_index("ix_component_occurrence_scan_id", "component_occurrence", ["scan_id"])
    op.create_index(
        "ix_component_occurrence_lookup", "component_occurrence", ["ecosystem", "normalized_name"]
    )


def downgrade() -> None:
    op.drop_table("component_occurrence")
