"""Risk at a glance: open findings and manifest health per project, and what to fix first."""

from dataclasses import dataclass, field

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from depradar.application.components import current_snapshots
from depradar.application.projects import get_project
from depradar.domain.entities import Finding, Inventory, Project, Scan
from depradar.domain.gate import LEVELS
from depradar.domain.security import Principal

# Most urgent first: known exploitation, then severity, then exploit likelihood.
SEVERITY_RANK = case({level: rank for rank, level in enumerate(LEVELS)}, value=Finding.severity)


@dataclass
class Manifest:
    """A monitored manifest's newest snapshot and its newest scan, if any."""

    inventory: Inventory
    scan: Scan | None

    @property
    def trustworthy(self) -> bool:
        """Only a complete, successful scan gives a full answer for the manifest."""
        return self.scan is not None and self.scan.status == "succeeded" and self.scan.complete


@dataclass
class ProjectSummary:
    project: Project
    # Open findings by severity, accepted risk excluded: the owner has already decided those.
    open_by_severity: dict[str, int] = field(default_factory=lambda: dict.fromkeys(LEVELS, 0))
    kev: int = 0
    acknowledged: int = 0
    risk_accepted: int = 0
    manifests: list[Manifest] = field(default_factory=list)

    @property
    def open_total(self) -> int:
        return sum(self.open_by_severity.values())

    @property
    def incomplete_manifests(self) -> int:
        return sum(not manifest.trustworthy for manifest in self.manifests)


@dataclass
class Portfolio:
    projects: list[ProjectSummary]
    urgent: list[Finding]
    project_names: dict[str, str]


def _summaries(db: Session, projects: list[Project]) -> list[ProjectSummary]:
    summaries = {project.id: ProjectSummary(project) for project in projects}
    if not summaries:
        return []
    for project_id, severity, workflow, kev, count in db.execute(
        select(
            Finding.project_id,
            Finding.severity,
            Finding.workflow_status,
            Finding.kev_known,
            func.count(),
        )
        .where(Finding.status == "open", Finding.project_id.in_(list(summaries)))
        .group_by(Finding.project_id, Finding.severity, Finding.workflow_status, Finding.kev_known)
    ).tuples():
        summary = summaries[project_id]
        if workflow == "risk_accepted":
            summary.risk_accepted += count
            continue
        level = severity if severity in LEVELS else "unknown"
        summary.open_by_severity[level] += count
        summary.kev += count if kev else 0
        summary.acknowledged += count if workflow == "acknowledged" else 0
    single = projects[0].id if len(projects) == 1 else None
    snapshots = current_snapshots(db, single)
    latest: dict[str, Scan] = {}
    if snapshots:
        for scan in db.scalars(
            select(Scan)
            .where(Scan.inventory_id.in_([inventory.id for inventory in snapshots]))
            .order_by(Scan.created_at.desc(), Scan.id.desc())
        ):
            latest.setdefault(scan.inventory_id, scan)
    for inventory in sorted(snapshots, key=lambda row: row.target_path):
        if inventory.project_id in summaries:
            summaries[inventory.project_id].manifests.append(
                Manifest(inventory, latest.get(inventory.id))
            )
    return list(summaries.values())


def portfolio(db: Session, principal: Principal, top: int) -> Portfolio:
    """Every project the principal may see, ranked by open risk, with the most urgent findings."""
    query = select(Project)
    if principal.project_id:
        query = query.where(Project.id == principal.project_id)
    projects = list(db.scalars(query.order_by(Project.name, Project.id)))
    summaries = sorted(
        _summaries(db, projects),
        key=lambda s: (
            -s.kev,
            *(-s.open_by_severity[level] for level in reversed(LEVELS)),
            s.project.name.lower(),
        ),
    )
    urgent: list[Finding] = []
    if projects:
        urgent = list(
            db.scalars(
                select(Finding)
                .where(
                    Finding.status == "open",
                    Finding.workflow_status != "risk_accepted",
                    Finding.project_id.in_([project.id for project in projects]),
                )
                .order_by(
                    Finding.kev_known.desc(),
                    SEVERITY_RANK.desc(),
                    func.coalesce(Finding.epss_score, -1).desc(),
                    Finding.first_seen_at,
                    Finding.id,
                )
                .limit(top)
            )
        )
    return Portfolio(summaries, urgent, {project.id: project.name for project in projects})


def project_overview(db: Session, principal: Principal, project_id: str) -> ProjectSummary:
    """One project's open risk and the health of each monitored manifest."""
    return _summaries(db, [get_project(db, project_id, principal)])[0]
