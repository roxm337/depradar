from depradar.domain.inventory import validate_inventory
from depradar.domain.scanning import ScannerReport, normalize


def test_transitive_alias_bridge_and_withdrawn_advisory() -> None:
    report = ScannerReport.model_validate(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "package", "version": "1.0.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {"id": "A", "aliases": ["B"]},
                                {"id": "C", "aliases": ["D"]},
                                {"id": "B", "aliases": ["D"]},
                                {"id": "withdrawn", "withdrawn": "2026-01-01"},
                            ],
                        }
                    ]
                }
            ]
        }
    )
    findings = normalize(report)
    assert len(findings) == 1
    assert findings[0].advisory_ids == ["A", "B", "C", "D"]
    assert findings[0].severity == "unknown"


def test_workspace_links_are_explicitly_partial() -> None:
    notes = validate_inventory(
        "package-lock.json",
        b"""{
      "lockfileVersion": 3, "packages": {"node_modules/local": {"link": true}}
    }""",
    )
    assert notes and "Local links" in notes[0]


def test_unpinned_package_parses_and_is_not_a_finding() -> None:
    # OSV-Scanner emits an empty version for an unpinned requirement (e.g. `jarm`, `pkg>=1`).
    # The report must still parse, and an unversioned package must never become a finding.
    report = ScannerReport.model_validate(
        {
            "results": [
                {
                    "packages": [
                        {"package": {"name": "jarm", "version": "", "ecosystem": "PyPI"}},
                        {
                            "package": {
                                "name": "litellm",
                                "version": "1.99.4",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-1"]}],
                        },
                    ]
                }
            ]
        }
    )
    findings = normalize(report)
    assert len(findings) == 1
    assert findings[0].package_name == "litellm" and findings[0].package_version == "1.99.4"


def test_unversioned_package_with_a_stray_advisory_is_still_skipped() -> None:
    report = ScannerReport.model_validate(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "ghost", "version": "", "ecosystem": "PyPI"},
                            "vulnerabilities": [{"id": "GHSA-y"}],
                        }
                    ]
                }
            ]
        }
    )
    assert normalize(report) == []
