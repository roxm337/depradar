"""Index the packages of monitored manifests and answer where a package is used."""

from dataclasses import dataclass

from sqlalchemy import and_, delete, distinct, func, insert, or_, select, update
from sqlalchemy.orm import Session

from depradar.application.errors import Invalid
from depradar.domain.components import components, normalize_name
from depradar.domain.entities import (
    ComponentOccurrence,
    Finding,
    Inventory,
    Project,
    Scan,
    new_id,
)
from depradar.domain.scanning import ScannerReport
from depradar.domain.security import Principal

MAX_MATCHES = 1000


def index_components(db: Session, scan: Scan, inventory: Inventory, report: ScannerReport) -> None:
    """Replace a snapshot's package rows with what this scan's report lists.

    Only a scan that returned a report reaches this point, so a failed rescan keeps the earlier
    rows. When the list is unchanged, the rows are re-attributed instead of rewritten.
    """
    found = components(report)
    existing = set(
        db.execute(
            select(
                ComponentOccurrence.ecosystem,
                ComponentOccurrence.normalized_name,
                ComponentOccurrence.version,
                ComponentOccurrence.name,
                ComponentOccurrence.purl,
            ).where(ComponentOccurrence.inventory_id == inventory.id)
        ).tuples()
    )
    wanted = {(c.ecosystem, c.normalized_name, c.version, c.name, c.purl) for c in found}
    if existing == wanted:
        db.execute(
            update(ComponentOccurrence)
            .where(ComponentOccurrence.inventory_id == inventory.id)
            .values(scan_id=scan.id)
        )
        return
    db.execute(delete(ComponentOccurrence).where(ComponentOccurrence.inventory_id == inventory.id))
    if not found:
        return
    # One bulk insert: a lockfile can list 10,000 packages, and this runs under the write barrier.
    db.execute(
        insert(ComponentOccurrence),
        [
            {
                "id": new_id(),
                "inventory_id": inventory.id,
                "project_id": inventory.project_id,
                "scan_id": scan.id,
                "ecosystem": c.ecosystem,
                "name": c.name,
                "normalized_name": c.normalized_name,
                "version": c.version,
                "purl": c.purl,
            }
            for c in found
        ],
    )


def current_snapshots(db: Session, project_id: str | None = None) -> list[Inventory]:
    """The newest monitored snapshot of every manifest path that is not retired."""
    newest: dict[tuple[str, str], Inventory] = {}
    query = select(Inventory).where(Inventory.kind == "monitor")
    if project_id is not None:
        query = query.where(Inventory.project_id == project_id)
    for inventory in db.scalars(query.order_by(Inventory.created_at.desc(), Inventory.id.desc())):
        newest.setdefault((inventory.project_id, inventory.target_path), inventory)
    return [inventory for inventory in newest.values() if inventory.retired_at is None]


@dataclass
class Snapshot:
    inventory: Inventory
    project: Project
    # The scan that produced the snapshot's rows; None while the snapshot is not indexed.
    scan: Scan | None


@dataclass
class Coverage:
    snapshots: list[Snapshot]
    # Ecosystems listed in the indexed current snapshots, for search filters.
    ecosystems: list[str]

    @property
    def not_indexed(self) -> list[Snapshot]:
        return [s for s in self.snapshots if s.scan is None]

    @property
    def partial(self) -> list[Snapshot]:
        return [s for s in self.snapshots if s.scan is not None and not s.scan.complete]


@dataclass
class Match:
    snapshot: Snapshot
    occurrence: ComponentOccurrence
    open_findings: int


@dataclass
class SearchResult:
    matches: list[Match]
    coverage: Coverage
    truncated: bool


def coverage(db: Session, principal: Principal) -> Coverage:
    """Which current snapshots are indexed, and by which scan.

    A project-restricted token sees its own project only, as everywhere else.
    """
    snapshots = current_snapshots(db, principal.project_id)
    ids = [inventory.id for inventory in snapshots]
    writers: dict[str, str] = {}
    ecosystems: list[str] = []
    if ids:
        # index_components writes or re-attributes a snapshot's rows together, so all of them
        # name the same scan; the aggregate only collapses them to one row per snapshot.
        for inventory_id, scan_id in db.execute(
            select(ComponentOccurrence.inventory_id, func.max(ComponentOccurrence.scan_id))
            .where(ComponentOccurrence.inventory_id.in_(ids))
            .group_by(ComponentOccurrence.inventory_id)
        ).tuples():
            writers[inventory_id] = scan_id
        ecosystems = sorted(
            db.scalars(
                select(distinct(ComponentOccurrence.ecosystem)).where(
                    ComponentOccurrence.inventory_id.in_(ids)
                )
            )
        )
    scans = (
        {
            scan.id: scan
            for scan in db.scalars(select(Scan).where(Scan.id.in_(list(writers.values()))))
        }
        if writers
        else {}
    )
    projects = {project.id: project for project in db.scalars(select(Project))}
    result = [
        Snapshot(
            inventory=inventory,
            project=projects[inventory.project_id],
            scan=scans.get(writers.get(inventory.id, "")),
        )
        for inventory in snapshots
    ]
    result.sort(key=lambda s: (s.project.name.lower(), s.inventory.target_path))
    return Coverage(result, ecosystems)


def search(
    db: Session,
    principal: Principal,
    name: str,
    ecosystem: str | None = None,
    version: str | None = None,
) -> SearchResult:
    """Where a package is used in current monitored manifests, with what qualifies the answer.

    Callers, assistants especially, send blank optional fields and their own casing of an
    ecosystem; neither may turn into an empty answer that reads as "not used".
    """
    if not name.strip():
        raise Invalid("Pass a package name")
    covered = coverage(db, principal)
    by_inventory = {s.inventory.id: s for s in covered.snapshots if s.scan is not None}
    wanted = (ecosystem or "").strip().casefold()
    ecosystems = (
        [value for value in covered.ecosystems if value.casefold() == wanted]
        if wanted
        else covered.ecosystems
    )
    # A blank version is no filter; unpinned packages are found by leaving it out.
    exact = (version or "").strip()
    if not by_inventory or not ecosystems:
        return SearchResult([], covered, truncated=False)
    names = or_(
        *(
            and_(
                ComponentOccurrence.ecosystem == value,
                ComponentOccurrence.normalized_name == normalize_name(value, name),
            )
            for value in ecosystems
        )
    )
    query = select(ComponentOccurrence).where(
        names, ComponentOccurrence.inventory_id.in_(list(by_inventory))
    )
    if exact:
        query = query.where(ComponentOccurrence.version == exact)
    rows = list(
        db.scalars(
            query.order_by(
                ComponentOccurrence.ecosystem,
                ComponentOccurrence.normalized_name,
                ComponentOccurrence.version,
                ComponentOccurrence.id,
            ).limit(MAX_MATCHES + 1)
        )
    )
    truncated = len(rows) > MAX_MATCHES
    rows = rows[:MAX_MATCHES]
    counts = open_findings(db, rows, by_inventory)
    matches = [
        Match(
            snapshot=by_inventory[row.inventory_id],
            occurrence=row,
            open_findings=counts.get(_finding_key(by_inventory[row.inventory_id], row), 0),
        )
        for row in rows
    ]
    matches.sort(
        key=lambda m: (
            m.occurrence.ecosystem,
            m.occurrence.normalized_name,
            m.occurrence.version,
            m.snapshot.project.name.lower(),
            m.snapshot.inventory.target_path,
        )
    )
    return SearchResult(matches, covered, truncated)


FindingKey = tuple[str, str, str, str, str]


def _finding_key(snapshot: Snapshot, row: ComponentOccurrence) -> FindingKey:
    return (
        snapshot.project.id,
        snapshot.inventory.target_path,
        row.ecosystem,
        row.name,
        row.version,
    )


def open_findings(
    db: Session, rows: list[ComponentOccurrence], snapshots: dict[str, Snapshot]
) -> dict[FindingKey, int]:
    """Open findings per matched package, keyed by project, manifest path, and package."""
    if not rows:
        return {}
    projects = {row.project_id for row in rows}
    names = {row.name for row in rows}
    wanted = {_finding_key(snapshots[row.inventory_id], row) for row in rows}
    counts: dict[FindingKey, int] = {}
    for project_id, target_path, ecosystem, package, version, count in db.execute(
        select(
            Finding.project_id,
            Finding.target_path,
            Finding.ecosystem,
            Finding.package_name,
            Finding.package_version,
            func.count(),
        )
        .where(
            Finding.status == "open",
            Finding.project_id.in_(sorted(projects)),
            Finding.package_name.in_(sorted(names)),
        )
        .group_by(
            Finding.project_id,
            Finding.target_path,
            Finding.ecosystem,
            Finding.package_name,
            Finding.package_version,
        )
    ).tuples():
        key = (project_id, target_path, ecosystem, package, version)
        if key in wanted:
            counts[key] = count
    return counts
