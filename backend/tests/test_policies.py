from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from depradar.application.scans import run_once
from depradar.domain.entities import SecurityPolicy
from depradar.domain.gate import GatePolicy, PolicySource
from depradar.domain.policy import PolicyRules, combine, enforce, tighten

from .conftest import Harness
from .test_ci_gate import advisory, ci_upload, evaluate, scanned
from .test_ci_tokens import bearer, create_token

INSTALLATION = PolicySource(scope="installation", project_id=None, version=3, policy_id="p")


def save(harness: Harness, rules: dict[str, Any], note: str = "") -> Any:
    response = harness.client.put(
        "/api/policies/installation",
        json={"rules": {**PolicyRules().model_dump(), **rules}, "note": note},
        headers=harness.headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def save_project(harness: Harness, project_id: str, rules: dict[str, Any] | None) -> Any:
    body = None if rules is None else {**PolicyRules().model_dump(), **rules}
    return harness.client.put(
        f"/api/policies/projects/{project_id}",
        json={"rules": body, "note": "client contract"},
        headers=harness.headers,
    )


def test_minimums_tighten_every_rule_and_explain_each_change() -> None:
    requested = GatePolicy(fail_on="critical", fail_on_kev=False, new_only=True)
    rules = PolicyRules(
        fail_on="high",
        fail_on_kev=True,
        fail_on_unknown=True,
        epss_threshold=0.2,
        fail_on_incomplete=True,
        require_monitored_manifests=True,
        allow_new_only=False,
        allow_ignore_acknowledged=False,
    )
    policy, changes = tighten(requested, rules, INSTALLATION)
    assert policy == GatePolicy(
        fail_on="high",
        fail_on_kev=True,
        fail_on_unknown=True,
        epss_threshold=0.2,
        fail_on_incomplete=True,
        require_monitored_manifests=True,
        new_only=False,
        ignore_acknowledged=False,
    )
    shown = {change.rule: (change.requested, change.enforced) for change in changes}
    assert shown["fail_on"] == ("critical", "high")
    assert shown["epss_threshold"] == ("off", "0.2")
    assert shown["new_only"] == ("on", "off")
    assert "ignore_acknowledged" not in shown  # the pipeline did not ask to ignore anything
    assert {change.source for change in changes} == {"installation policy v3"}


@pytest.mark.parametrize(
    ("requested", "rules"),
    [
        (GatePolicy(fail_on="low"), PolicyRules(fail_on="high")),
        (GatePolicy(fail_on="high"), PolicyRules(fail_on="none")),
        (GatePolicy(epss_threshold=0.05), PolicyRules(epss_threshold=0.5)),
        (GatePolicy(fail_on_incomplete=True), PolicyRules()),
        (GatePolicy(new_only=False), PolicyRules(allow_new_only=True)),
    ],
)
def test_a_stricter_pipeline_request_is_never_relaxed(
    requested: GatePolicy, rules: PolicyRules
) -> None:
    policy, changes = tighten(requested, rules, INSTALLATION)
    assert policy == requested and changes == []


def test_layers_combine_to_the_strictest_rule_and_credit_their_source() -> None:
    floor = PolicyRules(fail_on="high", epss_threshold=0.3, allow_new_only=False)
    project = PolicyRules(fail_on="medium", epss_threshold=0.5, fail_on_incomplete=True)
    combined = combine(floor, project)
    assert combined.fail_on == "medium" and combined.epss_threshold == 0.3
    assert combined.fail_on_incomplete and not combined.allow_new_only
    assert combine(PolicyRules(fail_on="critical"), PolicyRules()).fail_on == "critical"
    source = PolicySource(scope="project", project_id="x", version=1, policy_id="q")
    policy, changes = enforce(
        GatePolicy(fail_on="critical"), [(INSTALLATION, floor), (source, project)]
    )
    assert policy.fail_on == "medium"
    assert [(change.enforced, change.source) for change in changes if change.rule == "fail_on"] == [
        ("high", "installation policy v3"),
        ("medium", "project policy v1"),
    ]


def test_installation_policy_versions_are_immutable_and_owner_only(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    empty = harness.client.get("/api/policies").json()
    assert empty["installation"]["version"] == 0 and empty["installation"]["id"] is None
    assert empty["installation"]["rules"] == PolicyRules().model_dump()
    first = save(harness, {"fail_on": "high"}, "Agency baseline")
    second = save(harness, {"fail_on": "high", "fail_on_kev": True}, "Add KEV")
    assert (first["version"], second["version"]) == (1, 2)
    history = harness.client.get("/api/policies/versions").json()
    assert [row["note"] for row in history] == ["Add KEV", "Agency baseline"]
    assert harness.client.get("/api/policies").json()["installation"]["version"] == 2
    invalid = harness.client.put(
        "/api/policies/installation",
        json={"rules": {"epss_threshold": 2}, "note": ""},
        headers=harness.headers,
    )
    assert invalid.status_code == 422
    # Pipelines cannot read or change central policy, even with every scope.
    token = create_token(harness, ["projects:read", "projects:write", "scans:read"])
    assert anonymous.get("/api/policies", headers=bearer(token)).status_code == 401
    denied = anonymous.put(
        "/api/policies/installation",
        json={"rules": PolicyRules().model_dump(), "note": ""},
        headers=bearer(token),
    )
    assert denied.status_code == 401


def test_a_pipeline_cannot_lower_the_central_minimum(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    scan_id = ci_upload(anonymous, token).json()["scan"]["id"]
    run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: scanned(advisory("GHSA-high", "HIGH")),
    )
    relaxed = evaluate(anonymous, token, scan_id, fail_on="critical").json()
    assert relaxed["status"] == "pass"
    assert relaxed["policy_sources"] == [
        {"scope": "installation", "project_id": None, "version": 0, "policy_id": None}
    ]
    policy = save(harness, {"fail_on": "high"})
    enforced = evaluate(anonymous, token, scan_id, fail_on="critical", fail_on_kev=False).json()
    assert enforced["status"] == "fail" and enforced["violations"] == 1
    assert enforced["requested_policy"]["fail_on"] == "critical"
    assert enforced["policy"]["fail_on"] == "high"
    assert enforced["adjustments"] == [
        {
            "rule": "fail_on",
            "requested": "critical",
            "enforced": "high",
            "source": "installation policy v1",
        }
    ]
    assert enforced["policy_sources"][0]["policy_id"] == policy["id"]
    markdown = evaluate(anonymous, token, scan_id, fail_on="critical", format="markdown").text
    assert "Enforced by central policy" in markdown and "critical → high" in markdown


def test_project_policies_only_tighten_and_keep_history(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    save(harness, {"fail_on": "critical", "allow_new_only": True})
    created = save_project(harness, project_id, {"fail_on": "high", "allow_new_only": False})
    assert created.status_code == 200 and created.json()["version"] == 1
    overview = harness.client.get("/api/policies").json()
    assert [entry["project_id"] for entry in overview["projects"]] == [project_id]
    effective = overview["projects"][0]["effective"]
    assert effective["fail_on"] == "high" and not effective["allow_new_only"]
    token = create_token(harness)
    scan_id = ci_upload(anonymous, token).json()["scan"]["id"]
    run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: scanned(advisory("GHSA-high", "HIGH")),
    )
    result = evaluate(anonymous, token, scan_id, fail_on="none", new_only=True).json()
    assert result["status"] == "fail"
    assert result["policy"]["new_only"] is False
    assert [source["scope"] for source in result["policy_sources"]] == ["installation", "project"]
    # Removing the override records a new version and falls back to the installation minimum.
    removed = save_project(harness, project_id, None)
    assert removed.status_code == 200 and removed.json()["rules"] is None
    assert save_project(harness, project_id, None).status_code == 409
    assert harness.client.get("/api/policies").json()["projects"] == []
    versions = harness.client.get(f"/api/policies/versions?project_id={project_id}").json()
    assert [row["version"] for row in versions] == [2, 1]
    fallback = evaluate(anonymous, token, scan_id, fail_on="none").json()
    assert fallback["policy"]["fail_on"] == "critical" and fallback["status"] == "pass"
    missing = save_project(harness, "00000000-0000-4000-8000-000000000000", {})
    assert missing.status_code == 404
    deleted = harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers)
    assert deleted.status_code == 204
    with harness.factory() as db:
        assert db.scalar(select(func.count()).select_from(SecurityPolicy)) == 1


def test_required_manifests_cannot_be_skipped(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    web = ci_upload(anonymous, token).json()["scan"]["id"]
    ci_upload(anonymous, token, target_path="api/package-lock.json")
    while run_once(harness.factory, harness.settings, harness.store, lambda *_: scanned()):
        pass
    assert evaluate(anonymous, token, web).json()["status"] == "pass"
    save(harness, {"require_monitored_manifests": True})
    result = evaluate(anonymous, token, web).json()
    assert result["status"] == "fail" and result["violations"] == 0
    assert result["missing_manifests"] == [
        {
            "project_id": project_id,
            "project_name": "Example",
            "target_path": "api/package-lock.json",
        }
    ]
    assert result["reasons"] == [
        "Required manifest api/package-lock.json in Example was not scanned"
    ]
    junit = evaluate(anonymous, token, web, format="junit").text
    assert "DepRadar required manifests" in junit and "missing-manifest" in junit
    # Check uploads of every monitored manifest satisfy the rule; retired manifests drop out.
    check_web = ci_upload(anonymous, token, mode="check").json()["scan"]["id"]
    while run_once(harness.factory, harness.settings, harness.store, lambda *_: scanned()):
        pass
    assert evaluate(anonymous, token, check_web).json()["status"] == "fail"
    retired = harness.client.post(
        f"/api/projects/{project_id}/targets/retire",
        json={"target_path": "api/package-lock.json"},
        headers=harness.headers,
    )
    assert retired.status_code == 200, retired.text
    assert evaluate(anonymous, token, check_web).json()["status"] == "pass"
