"""Initial single-owner schema, frozen at revision creation.

Revision ID: 0001
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE auth_guard (
    id SERIAL NOT NULL, 
    failures INTEGER NOT NULL, 
    window_start TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CHECK (id = 1)
)
""")
    op.execute("""
CREATE TABLE owner (
    id INTEGER NOT NULL, 
    password_hash TEXT NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CHECK (id = 1)
)
""")
    op.execute("""
CREATE TABLE owner_session (
    token_hash VARCHAR(64) NOT NULL, 
    csrf_token VARCHAR(64) NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (token_hash)
)
""")
    op.execute("""
CREATE INDEX ix_owner_session_expires_at ON owner_session (expires_at)
""")
    op.execute("""
CREATE TABLE project (
    id VARCHAR(36) NOT NULL, 
    name VARCHAR(120) NOT NULL, 
    description VARCHAR(1000) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
)
""")
    op.execute("""
CREATE TABLE finding (
    id VARCHAR(36) NOT NULL, 
    project_id VARCHAR(36) NOT NULL, 
    target_filename VARCHAR(120) NOT NULL, 
    ecosystem VARCHAR(100) NOT NULL, 
    package_name TEXT NOT NULL, 
    package_version TEXT NOT NULL, 
    advisory_ids JSON NOT NULL, 
    summary TEXT NOT NULL, 
    severity VARCHAR(20) NOT NULL, 
    fixed_versions JSON NOT NULL, 
    status VARCHAR(20) NOT NULL, 
    evidence JSON NOT NULL, 
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    resolved_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (id), 
    FOREIGN KEY(project_id) REFERENCES project (id)
)
""")
    op.execute("""
CREATE INDEX ix_finding_project_id ON finding (project_id)
""")
    op.execute("""
CREATE TABLE inventory (
    id VARCHAR(36) NOT NULL, 
    project_id VARCHAR(36) NOT NULL, 
    filename VARCHAR(120) NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    size_bytes INTEGER NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(project_id) REFERENCES project (id)
)
""")
    op.execute("""
CREATE INDEX ix_inventory_project_id ON inventory (project_id)
""")
    op.execute("""
CREATE TABLE scan (
    id VARCHAR(36) NOT NULL, 
    inventory_id VARCHAR(36) NOT NULL, 
    project_id VARCHAR(36) NOT NULL, 
    status VARCHAR(20) NOT NULL, 
    complete BOOLEAN NOT NULL, 
    engine_version VARCHAR(120), 
    error VARCHAR(500), 
    package_count INTEGER NOT NULL, 
    coverage_notes JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    completed_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (id), 
    FOREIGN KEY(inventory_id) REFERENCES inventory (id), 
    FOREIGN KEY(project_id) REFERENCES project (id)
)
""")
    op.execute("""
CREATE INDEX ix_scan_project_id ON scan (project_id)
""")
    op.execute("""
CREATE INDEX ix_scan_inventory_id ON scan (inventory_id)
""")
    op.execute("""
CREATE TABLE change_event (
    id VARCHAR(36) NOT NULL, 
    finding_id VARCHAR(36) NOT NULL, 
    scan_id VARCHAR(36) NOT NULL, 
    kind VARCHAR(20) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(finding_id) REFERENCES finding (id), 
    FOREIGN KEY(scan_id) REFERENCES scan (id)
)
""")
    op.execute("""
CREATE INDEX ix_change_event_finding_id ON change_event (finding_id)
""")
    op.execute("""
CREATE TABLE job (
    id VARCHAR(36) NOT NULL, 
    scan_id VARCHAR(36) NOT NULL, 
    status VARCHAR(20) NOT NULL, 
    attempts INTEGER NOT NULL, 
    available_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    lease_until TIMESTAMP WITH TIME ZONE, 
    lease_token VARCHAR(36), 
    last_error VARCHAR(500), 
    PRIMARY KEY (id), 
    UNIQUE (scan_id), 
    FOREIGN KEY(scan_id) REFERENCES scan (id)
)
""")
    op.execute("""
CREATE INDEX ix_job_claim ON job (status, available_at)
""")
    op.execute("""
CREATE TABLE observation (
    id VARCHAR(36) NOT NULL, 
    scan_id VARCHAR(36) NOT NULL, 
    finding_id VARCHAR(36) NOT NULL, 
    evidence JSON NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (scan_id, finding_id), 
    FOREIGN KEY(scan_id) REFERENCES scan (id), 
    FOREIGN KEY(finding_id) REFERENCES finding (id)
)
""")
    op.execute("""
CREATE INDEX ix_observation_scan_id ON observation (scan_id)
""")
    op.execute("""
CREATE TABLE outbox_event (
    id VARCHAR(36) NOT NULL, 
    change_id VARCHAR(36) NOT NULL, 
    payload JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (change_id), 
    FOREIGN KEY(change_id) REFERENCES change_event (id)
)
""")
    op.execute("""
INSERT INTO auth_guard (id, failures, window_start) VALUES (1, 0, CURRENT_TIMESTAMP)
""")


def downgrade() -> None:
    op.drop_table("outbox_event")
    op.drop_table("observation")
    op.drop_table("job")
    op.drop_table("change_event")
    op.drop_table("scan")
    op.drop_table("inventory")
    op.drop_table("finding")
    op.drop_table("project")
    op.drop_table("owner_session")
    op.drop_table("owner")
    op.drop_table("auth_guard")
