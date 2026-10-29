"""Render CI gate results as SARIF 2.1.0, JUnit XML, and Markdown.

Advisory text, package names, and paths come from untrusted inputs: SARIF stays plain text,
JUnit is built with an XML serializer, and Markdown escapes every formatting character.
"""

import bisect
import hashlib
import json
import re
from collections.abc import Callable
from urllib.parse import quote
from xml.etree import ElementTree

from depradar import __version__
from depradar.domain.gate import GateItem, GatePolicy, GateResult, ScanGate

SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
LineFinder = Callable[[GateItem], int]


class LineIndex:
    """Best-effort lockfile line of a package entry, so annotations land on changed lines."""

    def __init__(self, content: bytes) -> None:
        self.text = content.decode("utf-8", errors="replace").lower()
        self.starts = [0, *(match.end() for match in re.finditer("\n", self.text))]

    def line_for(self, item: GateItem) -> int:
        name, version = item.package_name.lower(), item.package_version.lower()
        start = 0
        for _ in range(200):
            index = self.text.find(name, start)
            if index < 0 or not name:
                break
            start = index + 1
            end = index + len(name)
            if (index and self._word(self.text[index - 1], ".")) or (
                end < len(self.text) and self._word(self.text[end], "")
            ):
                continue
            line = bisect.bisect_right(self.starts, index)
            window = self.starts[line + 7] if line + 7 < len(self.starts) else len(self.text)
            if self._contains_version(version, index, window):
                return line
        return 1

    @staticmethod
    def _word(character: str, extra: str) -> bool:
        return character.isalnum() or character in "_-" + extra

    def _contains_version(self, version: str, start: int, end: int) -> bool:
        while version and (index := self.text.find(version, start, end)) >= 0:
            start = index + 1
            stop = index + len(version)
            before = self.text[index - 1] if index else " "
            after = self.text[stop] if stop < len(self.text) else " "
            if not (before.isdigit() or before == ".") and not (after.isalnum() or after in ".+-"):
                return True
        return False


def primary_id(item: GateItem) -> str:
    for prefix in ("GHSA-", "CVE-"):
        for advisory in item.advisory_ids:
            if advisory.startswith(prefix):
                return advisory
    return sorted(item.advisory_ids)[0]


def fingerprint(gate: ScanGate, item: GateItem) -> str:
    parts = (gate.project_id, gate.target_path, item.ecosystem, item.package_name)
    key = "\0".join((*parts, item.package_version, primary_id(item)))
    return hashlib.sha256(key.encode()).hexdigest()[:32] + ":1"


def describe(item: GateItem) -> str:
    fixed = ", ".join(item.fixed_versions) or "no fixed version published"
    summary = CONTROL.sub("", item.summary).strip() or primary_id(item)
    return (
        f"{item.package_name}@{item.package_version} ({item.ecosystem}) is affected by "
        f"{', '.join(item.advisory_ids)}: {summary[:500]}. Severity: {item.severity}. "
        f"Fixed in: {fixed}."
    )


def policy_text(policy: GatePolicy) -> str:
    rules = [] if policy.fail_on == "none" else [f"{policy.fail_on} severity and above"]
    if policy.fail_on_unknown and policy.fail_on != "none":
        rules.append("unknown severity")
    if policy.fail_on_kev:
        rules.append("CISA KEV")
    if policy.epss_threshold is not None:
        rules.append(f"EPSS >= {policy.epss_threshold:g}")
    if policy.fail_on_incomplete:
        rules.append("incomplete coverage")
    scope = "new findings only" if policy.new_only else "all open findings"
    return f"fail on {', '.join(rules) or 'nothing'} ({scope})"


def render_sarif(result: GateResult, lines: Callable[[ScanGate], LineFinder]) -> str:
    runs = []
    for gate in result.scans:
        line_for = lines(gate)
        rules: dict[str, dict[str, object]] = {}
        results = []
        for item in gate.items:
            if item.outcome == "ignored" and item.workflow_status == "risk_accepted":
                continue
            rule_id = primary_id(item)
            properties: dict[str, object] = {
                "tags": ["security", "dependency", item.ecosystem.lower()[:40]],
                "precision": "high",
            }
            if item.severity in SECURITY_SEVERITY:
                properties["security-severity"] = SECURITY_SEVERITY[item.severity]
            summary = CONTROL.sub("", item.summary).strip()[:1000] or rule_id
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": summary},
                    "fullDescription": {"text": summary},
                    "helpUri": "https://osv.dev/vulnerability/" + quote(rule_id, safe=""),
                    "help": {
                        "text": f"Advisories: {', '.join(item.advisory_ids)}. Upgrade to a "
                        "fixed version after checking compatibility; DepRadar does not verify "
                        "upgrade safety."
                    },
                    "properties": properties,
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIF_LEVEL.get(item.severity, "note"),
                    "message": {"text": describe(item)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": gate.target_path},
                                "region": {"startLine": line_for(item)},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": fingerprint(gate, item)},
                    "properties": {
                        "gate": item.outcome,
                        "reasons": item.reasons,
                        "kev": item.kev_known,
                        "epss": item.epss_score,
                        "new": item.new,
                    },
                }
            )
        notifications: list[dict[str, object]] = [
            {"message": {"text": note}} for note in gate.coverage_notes
        ]
        if gate.error:
            notifications.append({"message": {"text": gate.error}, "level": "error"})
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": "DepRadar",
                        "semanticVersion": __version__,
                        "rules": list(rules.values()),
                    }
                },
                # Distinct categories: code scanning no longer merges same-category runs.
                "automationDetails": {"id": f"depradar/{gate.target_path}/"},
                "invocations": [
                    {
                        "executionSuccessful": gate.error is None,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
            }
        )
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        },
        indent=2,
    )


def render_junit(result: GateResult) -> str:
    suites = ElementTree.Element("testsuites", name="DepRadar dependency gate")
    for gate in result.scans:
        suite = ElementTree.SubElement(
            suites, "testsuite", name=_xml(f"DepRadar {gate.target_path}")
        )
        if gate.error:
            error = _testcase(suite, gate, "dependency scan")
            ElementTree.SubElement(error, "error", message=_xml(gate.error))
        for item in gate.items:
            testcase = _testcase(
                suite, gate, f"{item.package_name}@{item.package_version} {primary_id(item)}"
            )
            if item.outcome == "violation":
                failure = ElementTree.SubElement(
                    testcase, "failure", message=_xml("; ".join(item.reasons)), type=item.severity
                )
                failure.text = _xml(describe(item))
            elif item.outcome == "ignored":
                ElementTree.SubElement(testcase, "skipped", message=_xml("; ".join(item.reasons)))
        if not gate.complete and not gate.error:
            coverage = _testcase(suite, gate, "scanner coverage")
            notes = _xml("\n".join(gate.coverage_notes))
            if result.policy.fail_on_incomplete:
                failure = ElementTree.SubElement(
                    coverage, "failure", message="Scanner coverage is incomplete"
                )
                failure.text = notes
            else:
                ElementTree.SubElement(coverage, "system-out").text = notes
        if not gate.items and not gate.error:
            _testcase(suite, gate, "no known vulnerabilities")
    for element in [*suites, suites]:
        cases = element.iter("testcase")
        counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        for testcase in cases:
            counts["tests"] += 1
            for kind, key in (("failure", "failures"), ("error", "errors"), ("skipped", "skipped")):
                counts[key] += testcase.find(kind) is not None
        for key, value in counts.items():
            element.set(key, str(value))
    # Declare UTF-8 explicitly; ElementTree would otherwise declare the locale encoding.
    body = ElementTree.tostring(suites, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body


def _testcase(suite: ElementTree.Element, gate: ScanGate, name: str) -> ElementTree.Element:
    return ElementTree.SubElement(
        suite, "testcase", classname=_xml("depradar." + gate.target_path), name=_xml(name)
    )


def render_markdown(result: GateResult, limit: int = 50) -> str:
    title = {"pass": "PASSED", "fail": "FAILED", "error": "ERROR"}[result.status]
    lines = [
        f"## DepRadar dependency gate: {title}",
        "",
        f"**{result.violations} violation{'s' if result.violations != 1 else ''}** · "
        f"{result.ignored} ignored · {result.below_threshold} below threshold · "
        f"policy: {_md(policy_text(result.policy))}",
        "",
    ]
    for gate in result.scans:
        lines.append(
            f"- `{gate.mode}` scan of {_md(gate.target_path)} in {_md(gate.project_name)}: "
            f"**{gate.status}**"
            + (f" — {_md(gate.error)}" if gate.error else "")
            + ("" if gate.complete or gate.error else " (incomplete coverage)")
        )
    rows = [(gate, item) for gate in result.scans for item in gate.items]
    if rows:
        lines += [
            "",
            "| Gate | Severity | Package | Advisories | Fixed in | Manifest | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for gate, item in rows[:limit]:
            lines.append(
                "| "
                + " | ".join(
                    _md(value)
                    for value in (
                        item.outcome.replace("_", " "),
                        item.severity,
                        f"{item.package_name}@{item.package_version}",
                        ", ".join(item.advisory_ids),
                        ", ".join(item.fixed_versions) or "none published",
                        gate.target_path,
                        "; ".join(item.reasons),
                    )
                )
                + " |"
            )
        if len(rows) > limit:
            lines.append(f"\n…and {len(rows) - limit} more. Open DepRadar for the full list.")
    notes = sorted({note for gate in result.scans for note in gate.coverage_notes})
    if notes:
        lines += ["", "**Coverage notes:** " + _md("; ".join(notes))]
    return "\n".join(lines) + "\n"


def _xml(value: str) -> str:
    return CONTROL.sub("", value)


def _md(value: str) -> str:
    """Escape CommonMark/GFM syntax, HTML, and table pipes in untrusted text."""
    value = CONTROL.sub("", value).replace("\n", " ").replace("\r", " ")[:300]
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|~])", r"\\\1", value)
