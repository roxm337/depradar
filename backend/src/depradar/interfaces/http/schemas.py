"""Request and response bodies of the HTTP API."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from depradar.domain.gate import GatePolicy, PolicySource
from depradar.domain.identity import Provider
from depradar.domain.policy import PolicyRules
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
    retired_at: datetime | None


class RetireTargetInput(BaseModel):
    target_path: str = Field(min_length=1, max_length=512)


class RetireTargetOutput(BaseModel):
    target_path: str
    retired_inventories: int
    resolved_findings: int


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


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_ids: list[UUID] = Field(min_length=1, max_length=50)
    policy: GatePolicy = Field(
        default_factory=GatePolicy,
        description="The pipeline's requested gate; central policies may tighten it.",
    )


class DecisionActor(BaseModel):
    kind: Literal["owner", "token", "identity"]
    name: str
    token_id: str | None
    verified: bool
    provider: str | None
    repository: str | None
    workflow: str | None
    ref: str | None
    event: str | None
    run_id: str | None
    run_url: str | None


class DecisionSummary(BaseModel):
    id: str
    created_at: datetime
    status: str
    project_id: str
    project_name: str
    revision: str | None
    commit: str | None
    mode: str
    violations: int
    ignored: int
    below_threshold: int
    missing_manifests: int
    actor: DecisionActor
    policy_sources: list[PolicySource]
    adjustments: int


class DecisionInputOutput(BaseModel):
    scan_id: str
    target_path: str
    filename: str
    mode: str
    sha256: str
    revision: str | None
    scan_status: str
    complete: bool
    engine_version: str | None
    completed_at: datetime | None
    coverage_notes: list[str]


class DecisionException(BaseModel):
    finding_id: str | None
    target_path: str
    package_name: str
    package_version: str
    advisory_ids: list[str]
    workflow_status: str
    reason: str
    risk_until: datetime | None


class DecisionDetail(DecisionSummary):
    inputs: list[DecisionInputOutput]
    exceptions: list[DecisionException]
    intelligence_updated_at: datetime | None
    result: dict[str, Any]


class PolicyVersionOutput(BaseModel):
    id: str | None
    scope: Literal["installation", "project"]
    project_id: str | None
    version: int
    rules: PolicyRules | None
    note: str
    created_at: datetime | None


class ProjectPolicyOutput(BaseModel):
    project_id: str
    policy: PolicyVersionOutput
    effective: PolicyRules


class PoliciesOutput(BaseModel):
    installation: PolicyVersionOutput
    projects: list[ProjectPolicyOutput]


class InstallationPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    rules: PolicyRules
    note: str = Field(default="", max_length=500)


class ProjectPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    rules: PolicyRules | None
    note: str = Field(default="", max_length=500)


class IdentityInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    project_id: UUID
    name: str = Field(default="", max_length=100)
    provider: Provider
    issuer: str | None = Field(default=None, max_length=300)
    repository: str = Field(
        min_length=3, max_length=300, pattern=r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$"
    )
    repository_id: str | None = Field(default=None, max_length=40, pattern=r"^\d*$")
    workflow: str | None = Field(default=None, max_length=300)
    monitor_ref: str | None = Field(default=None, max_length=300)


class IdentityOutput(Row):
    id: str
    project_id: str
    name: str
    provider: str
    issuer: str
    repository: str
    repository_id: str | None
    workflow: str | None
    monitor_ref: str | None
    created_at: datetime
    last_used_at: datetime | None
    disabled_at: datetime | None


class IdentitiesOutput(BaseModel):
    audience: str
    identities: list[IdentityOutput]


class OidcConfigOutput(BaseModel):
    audience: str = Field(description="Request OIDC identity tokens with this audience.")


class ExchangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id_token: str = Field(min_length=20, max_length=16384)
    project: str | None = Field(default=None, max_length=120)


class ExchangeOutput(BaseModel):
    token: str = Field(description="Short-lived bearer token; keep it masked in CI logs.")
    expires_at: datetime
    project_id: str
    project_name: str
    access: Literal["monitor", "check"]
    scopes: list[str]
    identity_id: str
