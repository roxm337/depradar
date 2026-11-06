"""What MCP tools return to an assistant.

Text that DepRadar did not write itself sits under an `untrusted` key: package names, versions,
manifest paths and revisions come from uploaded manifests (a pull request author controls
those), and advisory text comes from public feeds. It is cleaned of control characters and
capped in length, and the server instructions tell the assistant to treat it as data only.
"""

import re
import unicodedata
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from depradar.application.overview import Manifest, ProjectSummary
from depradar.domain.entities import Finding, Project, Scan
from depradar.domain.gate import GateItem, GatePolicy, GateResult, PolicyAdjustment, ScanGate

SHORT = 300
LONG = 1000
MAX_LIST = 50
# Large gates are summarized: counts stay exact, and the most severe items are listed first.
MAX_GATE_ITEMS = 100
_SPACE = re.compile(r"\s+")


def clean(value: str | None, limit: int = SHORT) -> str:
    """Strip control and formatting characters (including bidirectional overrides) and cap."""
    if not value:
        return ""
    text = "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} else character
        for character in value
    )
    text = _SPACE.sub(" ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def clean_list(values: list[str] | None, limit: int = SHORT) -> list[str]:
    return [clean(value, limit) for value in (values or [])[:MAX_LIST]]


# Projects, scans, and manifests


class ProjectItem(BaseModel):
    id: str
    name: str
    description: str
    monitoring_enabled: bool
    check_interval_hours: int
    created_at: datetime

    @classmethod
    def of(cls, project: Project) -> "ProjectItem":
        return cls(
            id=project.id,
            name=project.name,
            description=project.description,
            monitoring_enabled=project.monitoring_enabled,
            check_interval_hours=project.check_interval_hours,
            created_at=project.created_at,
        )


class ScanUntrusted(BaseModel):
    error: str
    coverage_notes: list[str]


class ScanItem(BaseModel):
    id: str
    project_id: str
    inventory_id: str
    mode: str = Field(description="`monitor` scans update findings; `check` scans never do.")
    status: str = Field(description="queued, running, succeeded, partial, failed, or superseded.")
    finished: bool
    complete: bool = Field(description="False when scanner coverage was partial.")
    package_count: int
    created_at: datetime
    completed_at: datetime | None
    untrusted: ScanUntrusted

    @classmethod
    def of(cls, scan: Scan) -> "ScanItem":
        return cls(
            id=scan.id,
            project_id=scan.project_id,
            inventory_id=scan.inventory_id,
            mode=scan.mode,
            status=scan.status,
            finished=scan.status not in {"queued", "running"},
            complete=scan.complete,
            package_count=scan.package_count,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            untrusted=ScanUntrusted(
                error=clean(scan.error, LONG), coverage_notes=clean_list(scan.coverage_notes)
            ),
        )


class ManifestUntrusted(BaseModel):
    filename: str
    path: str
    revision: str


class LatestScan(BaseModel):
    id: str
    status: str
    complete: bool
    completed_at: datetime | None


class ManifestItem(BaseModel):
    inventory_id: str
    uploaded_at: datetime
    latest_scan: LatestScan | None
    trustworthy: bool = Field(description="True only when the latest scan succeeded completely.")
    untrusted: ManifestUntrusted

    @classmethod
    def of(cls, manifest: Manifest) -> "ManifestItem":
        inventory, scan = manifest.inventory, manifest.scan
        return cls(
            inventory_id=inventory.id,
            uploaded_at=inventory.created_at,
            latest_scan=LatestScan(
                id=scan.id,
                status=scan.status,
                complete=scan.complete,
                completed_at=scan.completed_at,
            )
            if scan
            else None,
            trustworthy=manifest.trustworthy,
            untrusted=ManifestUntrusted(
                filename=clean(inventory.filename),
                path=clean(inventory.target_path),
                revision=clean(inventory.revision),
            ),
        )


class RiskCounts(BaseModel):
    open_by_severity: dict[str, int] = Field(
        description="Open findings by severity, excluding findings with accepted risk."
    )
    open_total: int
    kev: int = Field(description="Open findings listed in CISA Known Exploited Vulnerabilities.")
    acknowledged: int
    risk_accepted: int
    manifests: int
    incomplete_manifests: int = Field(
        description="Manifests whose latest scan is missing, failed, or partial. Their findings "
        "may be incomplete."
    )

    @classmethod
    def of(cls, summary: ProjectSummary) -> "RiskCounts":
        return cls(
            open_by_severity=summary.open_by_severity,
            open_total=summary.open_total,
            kev=summary.kev,
            acknowledged=summary.acknowledged,
            risk_accepted=summary.risk_accepted,
            manifests=len(summary.manifests),
            incomplete_manifests=summary.incomplete_manifests,
        )


# Findings


class FindingUntrusted(BaseModel):
    ecosystem: str
    package: str
    version: str
    manifest_path: str
    revision: str
    advisory_ids: list[str]
    summary: str
    fixed_versions: list[str]


class FindingItem(BaseModel):
    id: str
    project_id: str
    project_name: str | None = None
    severity: str
    kev: bool
    epss_score: float | None = Field(description="Probability of exploitation in 30 days.")
    epss_percentile: float | None
    status: str = Field(
        description="`open`, or `resolved` once a complete scan no longer finds it."
    )
    workflow_status: str = Field(description="open, acknowledged, or risk_accepted.")
    risk_until: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    untrusted: FindingUntrusted

    @classmethod
    def of(cls, finding: Finding, project_name: str | None = None) -> "FindingItem":
        return cls(
            id=finding.id,
            project_id=finding.project_id,
            project_name=project_name,
            severity=finding.severity,
            kev=finding.kev_known,
            epss_score=finding.epss_score,
            epss_percentile=finding.epss_percentile,
            status=finding.status,
            workflow_status=finding.workflow_status,
            risk_until=finding.risk_until,
            first_seen_at=finding.first_seen_at,
            last_seen_at=finding.last_seen_at,
            resolved_at=finding.resolved_at,
            untrusted=FindingUntrusted(
                ecosystem=clean(finding.ecosystem),
                package=clean(finding.package_name),
                version=clean(finding.package_version),
                manifest_path=clean(finding.target_path),
                revision=clean(finding.revision),
                advisory_ids=clean_list(finding.advisory_ids, 100),
                summary=clean(finding.summary, LONG),
                fixed_versions=clean_list(finding.fixed_versions, 100),
            ),
        )


class OwnerDecision(BaseModel):
    action: str
    note: str = Field(description="Written by the DepRadar owner.")
    expires_at: datetime | None
    created_at: datetime


class FindingDetail(FindingItem):
    cvss_vectors: list[str]
    decision_note: str = Field(description="The owner's latest triage note.")
    decisions: list[OwnerDecision]


class FindingList(BaseModel):
    findings: list[FindingItem]
    next_offset: int | None = Field(description="Pass as `offset` for the next page, if any.")


# Overview


class ProjectRisk(BaseModel):
    project: ProjectItem
    risk: RiskCounts


class PortfolioOverview(BaseModel):
    projects: list[ProjectRisk] = Field(description="Most at-risk first.")
    urgent: list[FindingItem] = Field(
        description="Open findings to fix first: known exploited, then by severity and EPSS. "
        "Accepted risk is excluded."
    )


class ProjectOverview(BaseModel):
    project: ProjectItem
    risk: RiskCounts
    manifests: list[ManifestItem]


# Package search


class PackageUntrusted(BaseModel):
    ecosystem: str
    name: str
    version: str = Field(description="Empty when the manifest does not pin a version.")
    purl: str
    manifest_path: str
    revision: str


class PackageMatch(BaseModel):
    project_id: str
    project_name: str
    inventory_id: str
    uploaded_at: datetime
    scan_complete: bool = Field(description="False when the indexing scan was partial.")
    open_findings: int
    untrusted: PackageUntrusted


class SearchCoverage(BaseModel):
    manifests: int
    indexed: int
    not_indexed: int = Field(description="Manifests not scanned since package indexing began.")
    partial: int


class PackageSearch(BaseModel):
    matches: list[PackageMatch]
    truncated: bool
    coverage: SearchCoverage
    note: str = (
        "Results reflect the last uploaded manifest of each monitored path, not what is "
        "deployed. Check-mode uploads are not included."
    )


# Gates


class GateItemUntrusted(BaseModel):
    ecosystem: str
    package: str
    version: str
    advisory_ids: list[str]
    summary: str
    fixed_versions: list[str]


class GateItemOut(BaseModel):
    finding_id: str | None
    outcome: str = Field(description="violation, ignored, or below_threshold.")
    severity: str
    kev: bool
    epss_score: float | None
    new: bool = Field(description="Not already open in the monitored project.")
    workflow_status: str
    reasons: list[str]
    untrusted: GateItemUntrusted

    @classmethod
    def of(cls, item: GateItem) -> "GateItemOut":
        return cls(
            finding_id=item.finding_id,
            outcome=item.outcome,
            severity=item.severity,
            kev=item.kev_known,
            epss_score=item.epss_score,
            new=item.new,
            workflow_status=item.workflow_status,
            reasons=clean_list(item.reasons),
            untrusted=GateItemUntrusted(
                ecosystem=clean(item.ecosystem),
                package=clean(item.package_name),
                version=clean(item.package_version),
                advisory_ids=clean_list(item.advisory_ids, 100),
                summary=clean(item.summary, LONG),
                fixed_versions=clean_list(item.fixed_versions, 100),
            ),
        )


class GateScanUntrusted(BaseModel):
    manifest_path: str
    revision: str
    error: str
    coverage_notes: list[str]


class GateScanOut(BaseModel):
    scan_id: str
    project_id: str
    status: str = Field(description="pass, fail, or error. Failed or superseded scans never pass.")
    scan_status: str
    complete: bool
    items: list[GateItemOut]
    items_truncated: bool
    untrusted: GateScanUntrusted

    @classmethod
    def of(cls, gate: ScanGate) -> "GateScanOut":
        return cls(
            scan_id=gate.scan_id,
            project_id=gate.project_id,
            status=gate.status,
            scan_status=gate.scan_status,
            complete=gate.complete,
            items=[GateItemOut.of(item) for item in gate.items[:MAX_GATE_ITEMS]],
            items_truncated=len(gate.items) > MAX_GATE_ITEMS,
            untrusted=GateScanUntrusted(
                manifest_path=clean(gate.target_path),
                revision=clean(gate.inventory_revision),
                error=clean(gate.error, LONG),
                coverage_notes=clean_list(gate.coverage_notes),
            ),
        )


class MissingManifestOut(BaseModel):
    project_id: str
    untrusted_manifest_path: str


class GateOut(BaseModel):
    decision_id: str | None
    status: str = Field(description="pass, fail, or error.")
    evaluated_at: datetime
    policy: GatePolicy = Field(description="The enforced policy, after central policies.")
    adjustments: list[PolicyAdjustment] = Field(
        description="Where a central policy tightened the requested policy."
    )
    reasons: list[str]
    violations: int
    ignored: int
    below_threshold: int
    missing_manifests: list[MissingManifestOut]
    scans: list[GateScanOut]

    @classmethod
    def of(cls, result: GateResult) -> "GateOut":
        return cls(
            decision_id=result.decision_id,
            status=result.status,
            evaluated_at=result.evaluated_at,
            policy=result.policy,
            adjustments=result.adjustments,
            reasons=clean_list(result.reasons),
            violations=result.violations,
            ignored=result.ignored,
            below_threshold=result.below_threshold,
            missing_manifests=[
                MissingManifestOut(
                    project_id=missing.project_id,
                    untrusted_manifest_path=clean(missing.target_path),
                )
                for missing in result.missing_manifests
            ],
            scans=[GateScanOut.of(gate) for gate in result.scans],
        )


class DecisionUntrusted(BaseModel):
    revision: str
    commit: str


class DecisionItem(BaseModel):
    id: str
    created_at: datetime
    status: str
    project_id: str
    project_name: str
    mode: str
    violations: int
    ignored: int
    below_threshold: int
    actor: str = Field(description="Who recorded the decision: owner, token, or identity.")
    untrusted: DecisionUntrusted


class DecisionList(BaseModel):
    decisions: list[DecisionItem]
    next_offset: int | None


class DecisionDetailOut(BaseModel):
    decision: DecisionItem
    gate: GateOut


# Check scans


class CheckStarted(BaseModel):
    scan_id: str
    project_id: str
    inventory_id: str
    status: str
    reused_inventory: bool = Field(description="True when identical content was already stored.")
    next_step: str = (
        "Call get_scan with this scan_id until `finished` is true, then preview_gate with it."
    )


def actor_label(actor: dict[str, Any]) -> str:
    kind = str(actor.get("kind", "unknown"))
    name = clean(str(actor.get("name") or ""), 100)
    return f"{kind}: {name}" if name else kind


# Changes that only increase coverage


class RescanUntrusted(BaseModel):
    path: str


class RescanItem(BaseModel):
    inventory_id: str
    scan_id: str
    status: str
    queued: bool = Field(
        description="False when a scan of this manifest was already queued or running; its ID "
        "is returned instead of queueing another."
    )
    untrusted: RescanUntrusted


class RescanStarted(BaseModel):
    project_id: str
    scans: list[RescanItem]
    next_step: str = (
        "Call get_scan with each scan_id until `finished` is true, then list_findings. Failed "
        "or partial scans never resolve findings."
    )


class MonitoringOut(BaseModel):
    project_id: str
    enabled: bool
    interval_hours: int
    next_check_at: datetime | None


class AlertsOut(BaseModel):
    project_id: str
    enabled: bool
    threshold: str = Field(description="The project's own threshold, or `inherit`.")
    effective_threshold: str = Field(
        description="The lowest severity that alerts immediately, after `inherit` is resolved."
    )
