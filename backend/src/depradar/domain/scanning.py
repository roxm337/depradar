from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    affected: list[dict[str, Any]] = Field(default_factory=list)
    database_specific: dict[str, Any] = Field(default_factory=dict)
    withdrawn: str | None = None


class PackageIdentity(BaseModel):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    ecosystem: str = Field(min_length=1)
    purl: str | None = None


class PackageResult(BaseModel):
    package: PackageIdentity
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class SourceResult(BaseModel):
    source: dict[str, Any] = Field(default_factory=dict)
    packages: list[PackageResult]


class ScannerReport(BaseModel):
    results: list[SourceResult]


class ScanResponse(BaseModel):
    report: ScannerReport
    engine_version: str
    complete: bool
    notes: list[str] = Field(default_factory=list)


class DetectedFinding(BaseModel):
    ecosystem: str
    package_name: str
    package_version: str
    purl: str | None
    advisory_ids: list[str]
    summary: str
    severity: str
    cvss_vectors: list[str]
    fixed_versions: list[str]
    evidence: list[dict[str, Any]]


def normalize(report: ScannerReport) -> list[DetectedFinding]:
    """Merge overlapping advisory aliases per exact package identity, retaining source evidence."""
    packages: dict[tuple[str, str, str], list[Vulnerability]] = {}
    for source in report.results:
        for result in source.packages:
            p = result.package
            packages.setdefault((p.ecosystem, p.name, p.version), []).extend(
                v for v in result.vulnerabilities if not v.withdrawn
            )
    output = []
    for (ecosystem, name, version), records in packages.items():
        groups: list[tuple[set[str], dict[str, Vulnerability]]] = []
        for record in records:
            ids = {record.id, *record.aliases}
            evidence = {record.id: record}
            remaining = []
            for previous_ids, previous_records in groups:
                if ids & previous_ids:
                    ids |= previous_ids
                    evidence.update(previous_records)
                else:
                    remaining.append((previous_ids, previous_records))
            # A bridge can connect more than one previously disjoint group.
            groups = remaining + [(ids, evidence)]
        for ids, evidence in groups:
            fixed: set[str] = set()
            severity = "unknown"
            levels = ["unknown", "low", "medium", "high", "critical"]
            for record in evidence.values():
                value = str(record.database_specific.get("severity", "unknown")).lower()
                if value in levels and levels.index(value) > levels.index(severity):
                    severity = value
                for affected in record.affected:
                    package = affected.get("package", {})
                    if package.get("name") != name or package.get("ecosystem") != ecosystem:
                        continue
                    for version_range in affected.get("ranges", []):
                        for event in version_range.get("events", []):
                            if isinstance(event.get("fixed"), str):
                                fixed.add(event["fixed"])
            output.append(
                DetectedFinding(
                    ecosystem=ecosystem,
                    package_name=name,
                    package_version=version,
                    advisory_ids=sorted(ids),
                    summary=next(
                        (v.summary for v in evidence.values() if v.summary), sorted(ids)[0]
                    ),
                    severity=severity,
                    purl=next(
                        (
                            result.package.purl
                            for source in report.results
                            for result in source.packages
                            if (
                                result.package.ecosystem,
                                result.package.name,
                                result.package.version,
                            )
                            == (ecosystem, name, version)
                            and result.package.purl
                        ),
                        None,
                    ),
                    cvss_vectors=sorted(
                        {
                            str(item["score"])
                            for record in evidence.values()
                            for item in (record.model_dump().get("severity") or [])
                            if isinstance(item, dict)
                            and isinstance(item.get("score"), str)
                            and item.get("score", "").startswith("CVSS:")
                        }
                    ),
                    fixed_versions=sorted(fixed),
                    evidence=[v.model_dump(exclude_none=True) for v in evidence.values()],
                )
            )
    return output
