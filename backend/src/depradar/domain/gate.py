"""CI/CD gate policy: which findings fail a pipeline, and why. Evaluation never changes findings."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from depradar.domain.entities import Finding, Inventory, Project, Scan

Threshold = Literal["none", "low", "medium", "high", "critical"]
GateStatus = Literal["pass", "fail", "error"]
Outcome = Literal["violation", "ignored", "below_threshold"]
LEVELS = ["unknown", "low", "medium", "high", "critical"]
FINISHED = {"succeeded", "partial", "failed", "superseded"}


class GatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fail_on: Threshold = "high"
    fail_on_unknown: bool = Field(
        default=False, description="Treat advisories without a severity as violations."
    )
    fail_on_kev: bool = Field(default=True, description="Fail on CISA KEV-listed CVEs.")
    epss_threshold: float | None = Field(default=None, ge=0, le=1)
    new_only: bool = Field(
        default=False, description="Ignore findings already open in the monitored project."
    )
    ignore_acknowledged: bool = False
    fail_on_incomplete: bool = Field(
        default=False, description="Fail when scanner coverage is partial."
    )


class GateItem(BaseModel):
    finding_id: str | None
    target_path: str
    ecosystem: str
    package_name: str
    package_version: str
    purl: str | None
    advisory_ids: list[str]
    summary: str
    severity: str
    fixed_versions: list[str]
    cvss_vectors: list[str]
    kev_known: bool
    epss_score: float | None
    workflow_status: str
    new: bool
    outcome: Outcome
    reasons: list[str]


class ScanGate(BaseModel):
    scan_id: str
    project_id: str
    project_name: str
    target_path: str
    inventory_revision: str | None
    mode: str
    scan_status: str
    complete: bool
    coverage_notes: list[str]
    error: str | None
    status: GateStatus
    items: list[GateItem]


class GateResult(BaseModel):
    status: GateStatus
    evaluated_at: datetime
    policy: GatePolicy
    violations: int
    ignored: int
    below_threshold: int
    scans: list[ScanGate]


@dataclass
class Candidate:
    """One detected vulnerability, with the monitored finding it matches, if any."""

    finding: Finding | None
    detected: dict[str, Any]
    kev_known: bool
    epss_score: float | None
    new: bool


def judge(candidate: Candidate, target_path: str, policy: GatePolicy, now: datetime) -> GateItem:
    finding, detected = candidate.finding, candidate.detected
    workflow = finding.workflow_status if finding else "open"
    severity = detected["severity"] if detected["severity"] in LEVELS else "unknown"
    reasons: list[str] = []
    if (
        workflow == "risk_accepted"
        and finding
        and (finding.risk_until is None or finding.risk_until > now)
    ):
        until = f" until {finding.risk_until:%Y-%m-%d}" if finding.risk_until else ""
        reasons.append("risk accepted" + until)
    elif workflow == "acknowledged" and policy.ignore_acknowledged:
        reasons.append("acknowledged")
    elif policy.new_only and not candidate.new:
        reasons.append("already open in the monitored project")
    outcome: Outcome
    if reasons:
        outcome = "ignored"
    else:
        level = LEVELS.index(severity)
        if policy.fail_on != "none":
            if level and level >= LEVELS.index(policy.fail_on):
                reasons.append(f"{severity} severity")
            elif not level and policy.fail_on_unknown:
                reasons.append("unknown severity")
        if policy.fail_on_kev and candidate.kev_known:
            reasons.append("listed in CISA KEV")
        if (
            policy.epss_threshold is not None
            and candidate.epss_score is not None
            and candidate.epss_score >= policy.epss_threshold
        ):
            reasons.append(f"EPSS {candidate.epss_score:.3f} >= {policy.epss_threshold:g}")
        outcome = "violation" if reasons else "below_threshold"
    return GateItem(
        finding_id=finding.id if finding else None,
        target_path=target_path,
        ecosystem=detected["ecosystem"],
        package_name=detected["package_name"],
        package_version=detected["package_version"],
        purl=detected.get("purl"),
        advisory_ids=detected["advisory_ids"],
        summary=detected.get("summary", ""),
        severity=severity,
        fixed_versions=detected.get("fixed_versions", []),
        cvss_vectors=detected.get("cvss_vectors", []),
        kev_known=candidate.kev_known,
        epss_score=candidate.epss_score,
        workflow_status=workflow,
        new=candidate.new,
        outcome=outcome,
        reasons=reasons,
    )


def scan_gate(
    scan: Scan,
    project: Project,
    inventory: Inventory,
    policy: GatePolicy,
    now: datetime,
    candidates: list[Candidate],
) -> ScanGate:
    def gate(status: GateStatus, error: str | None, items: list[GateItem]) -> ScanGate:
        return ScanGate(
            scan_id=scan.id,
            project_id=project.id,
            project_name=project.name,
            target_path=inventory.target_path,
            inventory_revision=inventory.revision,
            mode=scan.mode,
            scan_status=scan.status,
            complete=scan.complete,
            coverage_notes=scan.coverage_notes,
            error=error,
            status=status,
            items=items,
        )

    # Failed or replaced scans have no trustworthy result, so they can never pass a gate.
    if scan.status == "failed":
        return gate("error", scan.error or "Scan failed", [])
    if scan.status == "superseded":
        return gate(
            "error", "A newer upload of this manifest replaced this scan; rerun the pipeline", []
        )
    items = sorted(
        (judge(candidate, inventory.target_path, policy, now) for candidate in candidates),
        key=lambda item: (
            item.outcome != "violation",
            -LEVELS.index(item.severity if item.severity in LEVELS else "unknown"),
            item.package_name,
        ),
    )
    failed = any(item.outcome == "violation" for item in items) or (
        policy.fail_on_incomplete and not scan.complete
    )
    return gate("fail" if failed else "pass", None, items)


def gate_result(gates: list[ScanGate], policy: GatePolicy, now: datetime) -> GateResult:
    items = [item for gate in gates for item in gate.items]
    statuses = {gate.status for gate in gates}
    return GateResult(
        status="error" if "error" in statuses else "fail" if "fail" in statuses else "pass",
        evaluated_at=now,
        policy=policy,
        violations=sum(item.outcome == "violation" for item in items),
        ignored=sum(item.outcome == "ignored" for item in items),
        below_threshold=sum(item.outcome == "below_threshold" for item in items),
        scans=gates,
    )
