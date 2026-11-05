"""Central security policies: the owner's gate minimums for the installation and projects."""

from uuid import UUID

from fastapi import APIRouter, Depends

from depradar.application import policies
from depradar.domain.entities import SecurityPolicy
from depradar.domain.policy import PolicyRules
from depradar.interfaces.http.dependencies import Db, require_session
from depradar.interfaces.http.schemas import (
    InstallationPolicyInput,
    PoliciesOutput,
    PolicyVersionOutput,
    ProjectPolicyInput,
    ProjectPolicyOutput,
)

router = APIRouter(prefix="/api/policies", dependencies=[Depends(require_session)])


def version_output(policy: SecurityPolicy | None) -> PolicyVersionOutput:
    if policy is None:
        # Never saved: version 0 with the permissive defaults.
        return PolicyVersionOutput(
            id=None,
            scope="installation",
            project_id=None,
            version=0,
            rules=PolicyRules(),
            note="",
            created_at=None,
        )
    return PolicyVersionOutput(
        id=policy.id,
        scope="project" if policy.project_id else "installation",
        project_id=policy.project_id,
        version=policy.version,
        rules=policies.rules_of(policy),
        note=policy.note,
        created_at=policy.created_at,
    )


@router.get("", response_model=PoliciesOutput)
def overview(db: Db) -> PoliciesOutput:
    """The installation minimum and every project override with the minimum it results in."""
    installation, overrides = policies.overview(db)
    return PoliciesOutput(
        installation=version_output(installation),
        projects=[
            ProjectPolicyOutput(
                project_id=project_id, policy=version_output(policy), effective=effective
            )
            for project_id, policy, effective in overrides
        ],
    )


@router.put("/installation", response_model=PolicyVersionOutput)
def save_installation(body: InstallationPolicyInput, db: Db) -> PolicyVersionOutput:
    """Record a new installation policy version. Every pipeline is held to at least this."""
    return version_output(policies.save_installation(db, body.rules, body.note))


@router.put("/projects/{project_id}", response_model=PolicyVersionOutput)
def save_project(project_id: UUID, body: ProjectPolicyInput, db: Db) -> PolicyVersionOutput:
    """Record a project override; it can only tighten the installation policy. Null removes it."""
    return version_output(policies.save_project(db, str(project_id), body.rules, body.note))


@router.get("/versions", response_model=list[PolicyVersionOutput])
def versions(db: Db, project_id: UUID | None = None) -> list[PolicyVersionOutput]:
    """Version history, newest first: the installation's, or one project's."""
    rows = policies.versions(db, str(project_id) if project_id else None)
    return [version_output(row) for row in rows]
