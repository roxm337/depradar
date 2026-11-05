"""Versioned central security policies for the installation and individual projects."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict
from depradar.application.locking import lock_writes
from depradar.application.projects import get_project
from depradar.domain.entities import Project, SecurityPolicy
from depradar.domain.gate import PolicySource
from depradar.domain.policy import PolicyRules, combine

INSTALLATION = "installation"


def current(db: Session, scope_key: str) -> SecurityPolicy | None:
    return db.scalar(
        select(SecurityPolicy)
        .where(SecurityPolicy.scope_key == scope_key)
        .order_by(SecurityPolicy.version.desc())
        .limit(1)
    )


def rules_of(policy: SecurityPolicy | None) -> PolicyRules | None:
    if policy is None or policy.rules is None:
        return None
    return PolicyRules.model_validate(policy.rules)


def installation_rules(db: Session) -> PolicyRules:
    return rules_of(current(db, INSTALLATION)) or PolicyRules()


def source_of(policy: SecurityPolicy | None, project_id: str | None = None) -> PolicySource:
    return PolicySource(
        scope="project" if project_id else "installation",
        project_id=project_id,
        version=policy.version if policy else 0,
        policy_id=policy.id if policy else None,
    )


def minimums(db: Session, project_ids: list[str]) -> list[tuple[PolicySource, PolicyRules]]:
    """Central minimums for a gate: the installation policy, then each project's override.

    The installation is always listed, as version 0 before the owner first saves a policy, so
    every decision records which central policy it was judged under.
    """
    installation = current(db, INSTALLATION)
    found = [(source_of(installation), rules_of(installation) or PolicyRules())]
    for project_id in sorted(set(project_ids)):
        policy = current(db, project_id)
        rules = rules_of(policy)
        if rules is not None:
            found.append((source_of(policy, project_id), rules))
    return found


def _next_version(db: Session, scope_key: str) -> int:
    latest = db.scalar(
        select(func.max(SecurityPolicy.version)).where(SecurityPolicy.scope_key == scope_key)
    )
    return (latest or 0) + 1


def save_installation(db: Session, rules: PolicyRules, note: str) -> SecurityPolicy:
    lock_writes(db)
    policy = SecurityPolicy(
        scope_key=INSTALLATION,
        project_id=None,
        version=_next_version(db, INSTALLATION),
        rules=rules.model_dump(mode="json"),
        note=note,
    )
    db.add(policy)
    db.commit()
    return policy


def save_project(
    db: Session, project_id: str, rules: PolicyRules | None, note: str
) -> SecurityPolicy:
    """Record a new project version; None removes the override and keeps the history."""
    lock_writes(db)
    get_project(db, project_id)
    if rules is None and rules_of(current(db, project_id)) is None:
        raise Conflict("This project has no policy override to remove")
    policy = SecurityPolicy(
        scope_key=project_id,
        project_id=project_id,
        version=_next_version(db, project_id),
        rules=rules.model_dump(mode="json") if rules else None,
        note=note,
    )
    db.add(policy)
    db.commit()
    return policy


def overview(
    db: Session,
) -> tuple[SecurityPolicy | None, list[tuple[str, SecurityPolicy, PolicyRules]]]:
    """The installation policy and each active project override with its effective minimum."""
    installation = current(db, INSTALLATION)
    floor = rules_of(installation) or PolicyRules()
    overrides = []
    for project_id in db.scalars(select(Project.id).order_by(Project.name)):
        policy = current(db, project_id)
        rules = rules_of(policy)
        if policy is not None and rules is not None:
            overrides.append((project_id, policy, combine(floor, rules)))
    return installation, overrides


def versions(db: Session, project_id: str | None, limit: int = 50) -> list[SecurityPolicy]:
    if project_id:
        get_project(db, project_id)
    return list(
        db.scalars(
            select(SecurityPolicy)
            .where(SecurityPolicy.scope_key == (project_id or INSTALLATION))
            .order_by(SecurityPolicy.version.desc())
            .limit(limit)
        )
    )
