"""Request and response bodies of the HTTP API."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from depradar.domain.gate import GatePolicy
from depradar.domain.tokens import Scope


class PasswordInput(BaseModel):
    password: str = Field(min_length=12, max_length=128)


class ProjectInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)


class Row(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProjectOutput(Row):
    id: str
    name: str
    description: str
    created_at: datetime
    monitoring_enabled: bool
    check_interval_hours: int
    next_check_at: datetime | None
    notifications_enabled: bool
    alert_min_severity: str | None


class InventoryOutput(Row):
    id: str
    project_id: str
    filename: str
    target_path: str
    revision: str | None
    sha256: str
    size_bytes: int
    created_at: datetime
    kind: str


class ScanOutput(Row):
    id: str
    inventory_id: str
    project_id: str
    status: str
    complete: bool
    engine_version: str | None
    error: str | None
    package_count: int
    coverage_notes: list[str]
    created_at: datetime
    completed_at: datetime | None
    mode: str


class FindingOutput(Row):
    id: str
    project_id: str
    target_filename: str
    target_path: str
    revision: str | None
    ecosystem: str
    package_name: str
    package_version: str
    purl: str | None
    advisory_ids: list[str]
    summary: str
    severity: str
    cvss_vectors: list[str]
    epss_score: float | None
    epss_percentile: float | None
    kev_known: bool
    intel_updated_at: datetime | None
    fixed_versions: list[str]
    status: str
    evidence: list[dict[str, Any]]
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    workflow_status: str
    decision_note: str
    risk_until: datetime | None
    acknowledged_at: datetime | None


class JobOutput(Row):
    id: str
    scan_id: str
    status: str
    attempts: int
    available_at: datetime
    lease_until: datetime | None
    last_error: str | None


class DeliveryAttemptOutput(Row):
    id: str
    delivery_id: str
    attempt_number: int
    status: str
    started_at: datetime
    completed_at: datetime | None
    error_code: str | None
    provider_id: str | None


class UploadOutput(BaseModel):
    inventory: InventoryOutput
    scan: ScanOutput


class VerificationInput(BaseModel):
    code: str = Field(min_length=8, max_length=100)


class PolicyInput(BaseModel):
    immediate_min_severity: Literal["low", "medium", "high", "critical"] = "high"
    timezone: str = "UTC"
    digest_hour: int = Field(default=8, ge=0, le=23)
    include_details: bool = False
    quiet_hours_start: int | None = Field(default=None, ge=0, le=23)
    quiet_hours_end: int | None = Field(default=None, ge=0, le=23)

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Unknown IANA timezone") from exc
        return value

    @model_validator(mode="after")
    def quiet_hours_pair(self) -> "PolicyInput":
        if (self.quiet_hours_start is None) != (self.quiet_hours_end is None):
            raise ValueError("Set both quiet-hours boundaries or leave both blank")
        if self.quiet_hours_start is not None and self.quiet_hours_start == self.quiet_hours_end:
            raise ValueError("Quiet-hours start and end must differ")
        return self


class ProjectNotificationInput(BaseModel):
    enabled: bool = True
    immediate_min_severity: Literal["inherit", "low", "medium", "high", "critical"] = "inherit"


class ProjectNotificationOutput(Row):
    enabled: bool
    immediate_min_severity: str | None


class DeliveryOutput(Row):
    id: str
    connector_id: str
    project_id: str | None
    kind: str
    status: str
    attempts: int
    available_at: datetime
    last_error: str | None
    provider_id: str | None
    created_at: datetime
    accepted_at: datetime | None


class OperationsHealth(BaseModel):
    database: str
    worker: str
    worker_heartbeat_at: datetime | None
    scanner: str
    scanner_checked_at: datetime | None
    queued_jobs: int
    running_jobs: int
    failed_jobs: int
    oldest_queued_job_at: datetime | None
    due_projects: int
    queued_deliveries: int
    failed_deliveries: int
    intelligence_updated_at: datetime | None


class MonitoringInput(BaseModel):
    enabled: bool
    interval_hours: int = Field(default=24, ge=1, le=168)


class AcknowledgeInput(BaseModel):
    note: str = Field(default="", max_length=2000)


class RiskInput(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime


class RetentionInput(BaseModel):
    scan_days: int = Field(default=30, ge=1, le=3650)
    delivery_days: int = Field(default=30, ge=1, le=3650)


class TokenInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    scopes: list[Scope] = Field(min_length=1)
    project_id: UUID | None = None
    expires_in_days: int = Field(default=90, ge=1, le=365)


class TokenOutput(Row):
    id: str
    name: str
    display_prefix: str
    scopes: list[str]
    project_id: str | None
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class CreatedTokenOutput(TokenOutput):
    token: str = Field(description="Shown once. Store it as a CI secret; DepRadar keeps a hash.")


class CiUploadOutput(BaseModel):
    project: ProjectOutput
    inventory: InventoryOutput
    scan: ScanOutput
    project_created: bool
    reused_inventory: bool


class EvaluationQuery(GatePolicy):
    scan_id: list[UUID] = Field(min_length=1, max_length=50)
    format: Literal["json", "sarif", "junit", "markdown"] = "json"
