"""Monitoring, notification delivery, decisions, and maintenance.

Revision ID: 0002
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
ALTER TABLE project ADD COLUMN monitoring_enabled BOOLEAN NOT NULL DEFAULT false
""")
    op.execute("""
ALTER TABLE project ADD COLUMN check_interval_hours INTEGER NOT NULL DEFAULT 24
""")
    op.execute("""
ALTER TABLE project ADD COLUMN next_check_at TIMESTAMP WITH TIME ZONE
""")
    op.execute("""
ALTER TABLE finding ADD COLUMN workflow_status VARCHAR(20) NOT NULL DEFAULT 'open'
""")
    op.execute("""
ALTER TABLE finding ADD COLUMN decision_note TEXT NOT NULL DEFAULT ''
""")
    op.execute("""
ALTER TABLE finding ADD COLUMN risk_until TIMESTAMP WITH TIME ZONE
""")
    op.execute("""
ALTER TABLE finding ADD COLUMN acknowledged_at TIMESTAMP WITH TIME ZONE
""")
    op.execute("""
ALTER TABLE outbox_event ADD COLUMN processed_at TIMESTAMP WITH TIME ZONE
""")
    op.execute("""
CREATE TABLE connector (
    id VARCHAR(20) NOT NULL, 
    config JSON NOT NULL, 
    enabled BOOLEAN NOT NULL, 
    generation INTEGER NOT NULL, 
    verified_at TIMESTAMP WITH TIME ZONE, 
    challenge_hash VARCHAR(64), 
    challenge_expires_at TIMESTAMP WITH TIME ZONE, 
    update_offset INTEGER NOT NULL, 
    next_send_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id)
)
""")
    op.execute("""
CREATE TABLE file_deletion (
    inventory_id VARCHAR(36) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (inventory_id)
)
""")
    op.execute("""
CREATE TABLE notification_policy (
    id INTEGER NOT NULL, 
    immediate_min_severity VARCHAR(20) NOT NULL, 
    timezone VARCHAR(100) NOT NULL, 
    digest_hour INTEGER NOT NULL, 
    next_digest_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    include_details BOOLEAN NOT NULL, 
    PRIMARY KEY (id), 
    CHECK (id = 1)
)
""")
    op.execute("""
CREATE TABLE system_state (
    id INTEGER NOT NULL, 
    last_housekeeping_at TIMESTAMP WITH TIME ZONE, 
    scan_retention_days INTEGER NOT NULL, 
    delivery_retention_days INTEGER NOT NULL, 
    PRIMARY KEY (id), 
    CHECK (id = 1)
)
""")
    op.execute("""
CREATE TABLE finding_decision (
    id VARCHAR(36) NOT NULL, 
    finding_id VARCHAR(36) NOT NULL, 
    action VARCHAR(30) NOT NULL, 
    note TEXT NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(finding_id) REFERENCES finding (id)
)
""")
    op.execute("""
CREATE INDEX ix_finding_decision_finding_id ON finding_decision (finding_id)
""")
    op.execute("""
CREATE TABLE delivery (
    id VARCHAR(36) NOT NULL, 
    connector_id VARCHAR(20) NOT NULL, 
    generation INTEGER NOT NULL, 
    project_id VARCHAR(36), 
    outbox_id VARCHAR(36), 
    kind VARCHAR(20) NOT NULL, 
    subject VARCHAR(200) NOT NULL, 
    body TEXT NOT NULL, 
    status VARCHAR(20) NOT NULL, 
    attempts INTEGER NOT NULL, 
    available_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    lease_until TIMESTAMP WITH TIME ZONE, 
    lease_token VARCHAR(36), 
    provider_id VARCHAR(200), 
    last_error VARCHAR(200), 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    accepted_at TIMESTAMP WITH TIME ZONE, 
    batch_id VARCHAR(36), 
    PRIMARY KEY (id), 
    UNIQUE (outbox_id, connector_id, generation), 
    FOREIGN KEY(connector_id) REFERENCES connector (id), 
    FOREIGN KEY(project_id) REFERENCES project (id), 
    FOREIGN KEY(outbox_id) REFERENCES outbox_event (id)
)
""")
    op.execute("""
CREATE INDEX ix_delivery_project_id ON delivery (project_id)
""")
    op.execute("""
CREATE INDEX ix_delivery_batch_id ON delivery (batch_id)
""")
    op.execute("""
CREATE INDEX ix_delivery_claim ON delivery (status, available_at)
""")
    op.execute("""
CREATE INDEX ix_delivery_outbox_id ON delivery (outbox_id)
""")
    op.execute("""
INSERT INTO system_state (id, scan_retention_days, delivery_retention_days) VALUES (1, 30, 30)
""")
    op.execute("""
INSERT INTO notification_policy
(id, immediate_min_severity, timezone, digest_hour, next_digest_at, include_details)
VALUES (1, 'high', 'UTC', 8, CURRENT_TIMESTAMP, false)
""")


def downgrade() -> None:
    op.drop_table("delivery")
    op.drop_table("finding_decision")
    op.drop_table("system_state")
    op.drop_table("notification_policy")
    op.drop_table("file_deletion")
    op.drop_table("connector")
    op.drop_column("outbox_event", "processed_at")
    op.drop_column("finding", "workflow_status")
    op.drop_column("finding", "decision_note")
    op.drop_column("finding", "risk_until")
    op.drop_column("finding", "acknowledged_at")
    op.drop_column("project", "monitoring_enabled")
    op.drop_column("project", "check_interval_hours")
    op.drop_column("project", "next_check_at")
