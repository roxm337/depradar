"""Packages a scanner reported for a manifest, keyed so equivalent names match across projects."""

import re
from dataclasses import dataclass

from depradar.domain.scanning import ScannerReport

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: str, name: str) -> str:
    """Return the form under which an ecosystem's registry treats two names as the same package.

    Only ecosystems whose registries define name equivalence are folded; every other name is
    compared exactly, so two distinct packages are never merged by a guess.
    """
    name = name.strip()
    if ecosystem == "PyPI":
        return _PYPI_SEPARATORS.sub("-", name).lower()  # PEP 503
    if ecosystem == "crates.io":
        return name.lower().replace("-", "_")  # crates.io treats case and -/_ as equivalent
    if ecosystem in {"Packagist", "NuGet", "Pub"}:
        return name.lower()
    return name


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    normalized_name: str
    # Empty when the manifest left the package unpinned.
    version: str
    purl: str | None


def components(report: ScannerReport) -> list[Component]:
    """Every package in the report once per ecosystem, normalized name, and version.

    Unpinned packages are kept: they cannot match advisories, but they still answer where a
    package is used. The first spelling and package URL seen for a package are kept for display.
    """
    found: dict[tuple[str, str, str], Component] = {}
    for source in report.results:
        for result in source.packages:
            package = result.package
            normalized = normalize_name(package.ecosystem, package.name)
            key = (package.ecosystem, normalized, package.version)
            if key not in found:
                found[key] = Component(
                    ecosystem=package.ecosystem,
                    name=package.name,
                    normalized_name=normalized,
                    version=package.version,
                    purl=package.purl,
                )
    return sorted(found.values(), key=lambda c: (c.ecosystem, c.normalized_name, c.version))
