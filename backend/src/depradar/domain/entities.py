"""Persistent entities. SQLAlchemy maps them; it is the one framework the core uses."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Dialect,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class UtcTimestamp(TypeDecorator[datetime]):
    """Keep UTC awareness even when the lightweight unit-test dialect drops offsets."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class AuthGuard(Base):
    __tablename__ = "auth_guard"
    __table_args__ = (CheckConstraint("id = 1"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    failures: Mapped[int] = mapped_column(default=0)
    window_start: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class Owner(Base):
    __tablename__ = "owner"
    __table_args__ = (CheckConstraint("id = 1"),)
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class OwnerSession(Base):
    __tablename__ = "owner_session"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(UtcTimestamp(), index=True)


class Project(Base):
    __tablename__ = "project"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    monitoring_enabled: Mapped[bool] = mapped_column(default=False)
    check_interval_hours: Mapped[int] = mapped_column(default=24)
    next_check_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    notifications_enabled: Mapped[bool] = mapped_column(default=True)
    alert_min_severity: Mapped[str | None] = mapped_column(String(20))


class Inventory(Base):
    __tablename__ = "inventory"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    filename: Mapped[str] = mapped_column(String(120))
    target_path: Mapped[str] = mapped_column(String(512), default="")
    revision: Mapped[str | None] = mapped_column(String(200))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int]
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    # "monitor" inventories define project state; "check" inventories only answer CI gates.
    kind: Mapped[str] = mapped_column(String(20), default="monitor")


class Scan(Base):
    __tablename__ = "scan"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    inventory_id: Mapped[str] = mapped_column(ForeignKey("inventory.id"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    complete: Mapped[bool] = mapped_column(default=False)
    engine_version: Mapped[str | None] = mapped_column(String(120))
    error: Mapped[str | None] = mapped_column(String(500))
    package_count: Mapped[int] = mapped_column(default=0)
    coverage_notes: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    mode: Mapped[str] = mapped_column(String(20), default="monitor")
    # Check-mode scans keep normalized detections here instead of changing findings.
    results: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)


class Job(Base):
    __tablename__ = "job"
    __table_args__ = (Index("ix_job_claim", "status", "available_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    attempts: Mapped[int] = mapped_column(default=0)
    available_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    lease_until: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    lease_token: Mapped[str | None] = mapped_column(String(36))
    last_error: Mapped[str | None] = mapped_column(String(500))


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    target_filename: Mapped[str] = mapped_column(String(120))
    target_path: Mapped[str] = mapped_column(String(512), default="")
    revision: Mapped[str | None] = mapped_column(String(200))
    ecosystem: Mapped[str] = mapped_column(String(100))
    package_name: Mapped[str] = mapped_column(Text)
    package_version: Mapped[str] = mapped_column(Text)
    purl: Mapped[str | None] = mapped_column(Text)
    advisory_ids: Mapped[list[str]] = mapped_column(JSON)
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="unknown")
    cvss_vectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    kev_known: Mapped[bool] = mapped_column(default=False)
    intel_updated_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="open")
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    workflow_status: Mapped[str] = mapped_column(String(20), default="open")
    decision_note: Mapped[str] = mapped_column(Text, default="")
    risk_until: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    acknowledged_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())


class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    cve_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    kev_known: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class Observation(Base):
    __tablename__ = "observation"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON)


class ChangeEvent(Base):
    __tablename__ = "change_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    kind: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class OutboxEvent(Base):
    __tablename__ = "outbox_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    change_id: Mapped[str] = mapped_column(ForeignKey("change_event.id"), unique=True)
    payload: Mapped[dict[str, str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    processed_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())


class SystemState(Base):
    __tablename__ = "system_state"
    __table_args__ = (CheckConstraint("id = 1"),)
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    last_housekeeping_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    scan_retention_days: Mapped[int] = mapped_column(default=30)
    delivery_retention_days: Mapped[int] = mapped_column(default=30)
    last_worker_heartbeat_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    last_scanner_check_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    scanner_available: Mapped[bool | None] = mapped_column()
    last_intelligence_refresh_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    next_intelligence_refresh_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())


class NotificationPolicy(Base):
    __tablename__ = "notification_policy"
    __table_args__ = (CheckConstraint("id = 1"),)
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    immediate_min_severity: Mapped[str] = mapped_column(String(20), default="high")
    timezone: Mapped[str] = mapped_column(String(100), default="UTC")
    digest_hour: Mapped[int] = mapped_column(default=8)
    next_digest_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    include_details: Mapped[bool] = mapped_column(default=False)
    quiet_hours_start: Mapped[int | None] = mapped_column()
    quiet_hours_end: Mapped[int | None] = mapped_column()


class Connector(Base):
    __tablename__ = "connector"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(default=True)
    generation: Mapped[int] = mapped_column(default=1)
    verified_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    challenge_hash: Mapped[str | None] = mapped_column(String(64))
    challenge_expires_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    update_offset: Mapped[int] = mapped_column(default=0)
    next_send_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class Delivery(Base):
    __tablename__ = "delivery"
    __table_args__ = (
        UniqueConstraint("outbox_id", "connector_id", "generation"),
        Index("ix_delivery_claim", "status", "available_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    connector_id: Mapped[str] = mapped_column(ForeignKey("connector.id"))
    generation: Mapped[int]
    project_id: Mapped[str | None] = mapped_column(ForeignKey("project.id"), index=True)
    outbox_id: Mapped[str | None] = mapped_column(ForeignKey("outbox_event.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="alert")
    subject: Mapped[str] = mapped_column(String(200), default="DepRadar update")
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    attempts: Mapped[int] = mapped_column(default=0)
    available_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    lease_until: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    lease_token: Mapped[str | None] = mapped_column(String(36))
    provider_id: Mapped[str | None] = mapped_column(String(200))
    last_error: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    accepted_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    batch_id: Mapped[str | None] = mapped_column(String(36), index=True)


class DeliveryAttempt(Base):
    __tablename__ = "delivery_attempt"
    __table_args__ = (UniqueConstraint("delivery_id", "attempt_number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    delivery_id: Mapped[str] = mapped_column(
        ForeignKey("delivery.id", ondelete="CASCADE"), index=True
    )
    attempt_number: Mapped[int]
    status: Mapped[str] = mapped_column(String(20), default="sending")
    started_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    error_code: Mapped[str | None] = mapped_column(String(200))
    provider_id: Mapped[str | None] = mapped_column(String(200))


class FindingDecision(Base):
    __tablename__ = "finding_decision"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"), index=True)
    action: Mapped[str] = mapped_column(String(30))
    note: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class FileDeletion(Base):
    __tablename__ = "file_deletion"
    inventory_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)


class ApiToken(Base):
    """Scoped automation credential; only a SHA-256 digest of the secret is stored."""

    __tablename__ = "api_token"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    display_prefix: Mapped[str] = mapped_column(String(24))
    scopes: Mapped[list[str]] = mapped_column(JSON)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("project.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcTimestamp(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcTimestamp())
    last_used_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
    revoked_at: Mapped[datetime | None] = mapped_column(UtcTimestamp())
