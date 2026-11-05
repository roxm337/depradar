"""Trusted CI identities: exchange a verified OIDC job token for short-lived, scoped access."""

from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict, Forbidden, Invalid, NotFound, Unauthorized
from depradar.application.locking import lock_writes
from depradar.application.ports import IdentityRejected, IdentityVerifier
from depradar.application.projects import get_project
from depradar.config import Settings
from depradar.domain.entities import ApiToken, Project, TrustedIdentity, utcnow
from depradar.domain.identity import (
    DEFAULT_ISSUERS,
    Access,
    IdentityMismatch,
    VerifiedRun,
    access_for,
    canonical_ref,
    canonical_workflow,
    same_repository,
    verified_run,
)
from depradar.domain.security import digest
from depradar.domain.tokens import DISPLAY_LENGTH, generate_token

TOKEN_LIFETIME = timedelta(minutes=30)
CHECK_SCOPES = ["findings:read", "inventories:check", "projects:read", "scans:read"]
MONITOR_SCOPES = sorted([*CHECK_SCOPES, "inventories:write"])


def audience(settings: Settings) -> str:
    """The value pipelines request as their OIDC token audience; unique to this installation."""
    return (settings.oidc_audience or settings.dashboard_url).strip().rstrip("/")


def list_identities(db: Session) -> list[TrustedIdentity]:
    return list(
        db.scalars(
            select(TrustedIdentity).order_by(
                TrustedIdentity.disabled_at.is_not(None),
                TrustedIdentity.repository,
                TrustedIdentity.created_at,
            )
        )
    )


def _issuer(provider: str, issuer: str | None) -> str:
    value = (issuer or DEFAULT_ISSUERS[provider]).strip().rstrip("/")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
        raise Invalid("The issuer must be an https:// URL without a query")
    return value


def create_identity(
    db: Session,
    project_id: str,
    provider: str,
    repository: str,
    *,
    name: str = "",
    issuer: str | None = None,
    repository_id: str | None = None,
    workflow: str | None = None,
    monitor_ref: str | None = None,
) -> TrustedIdentity:
    lock_writes(db)
    get_project(db, project_id)
    repository = repository.strip().strip("/")
    issuer = _issuer(provider, issuer)
    duplicate = db.scalar(
        select(TrustedIdentity.id).where(
            TrustedIdentity.project_id == project_id,
            TrustedIdentity.provider == provider,
            TrustedIdentity.issuer == issuer,
            TrustedIdentity.repository == repository,
            TrustedIdentity.disabled_at.is_(None),
        )
    )
    if duplicate:
        raise Conflict("This repository is already trusted for the project")
    identity = TrustedIdentity(
        project_id=project_id,
        name=name.strip() or repository,
        provider=provider,
        issuer=issuer,
        repository=repository,
        repository_id=(repository_id or "").strip() or None,
        workflow=canonical_workflow(workflow),
        monitor_ref=canonical_ref(monitor_ref),
    )
    db.add(identity)
    db.commit()
    return identity


def disable_identity(db: Session, identity_id: str) -> None:
    """Stop trusting the identity and revoke the short-lived tokens it already issued."""
    lock_writes(db)
    identity = db.get(TrustedIdentity, identity_id)
    if identity is None:
        raise NotFound("Identity not found")
    now = utcnow()
    if identity.disabled_at is None:
        identity.disabled_at = now
    db.execute(
        update(ApiToken)
        .where(ApiToken.identity_id == identity.id, ApiToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    db.commit()


def _project_matches(project: Project, reference: str) -> bool:
    try:
        return project.id == str(UUID(reference))
    except ValueError:
        return project.name == reference


def exchange(
    db: Session,
    verifier: IdentityVerifier,
    settings: Settings,
    id_token: str,
    project_reference: str | None,
) -> tuple[ApiToken, str, Access, Project, VerifiedRun]:
    """Verify a CI job's OIDC token and issue a 30-minute token bound to one project.

    Pull and merge request runs, other branches, tags, and untrusted events get check-only
    access. Only the trusted workflow on the monitor branch may update monitored state. The
    project reference only chooses between several projects that trust the same repository.
    """
    active = list(db.scalars(select(TrustedIdentity).where(TrustedIdentity.disabled_at.is_(None))))
    if not active:
        raise Unauthorized("No trusted CI identities are configured")
    # Verify before taking the write barrier: fetching signing keys may wait on the network.
    try:
        claims: dict[str, Any] = verifier(
            id_token, {identity.issuer for identity in active}, audience(settings)
        )
    except IdentityRejected as exc:
        raise Unauthorized(str(exc)) from exc
    issuer = str(claims.get("iss", ""))
    matches: list[tuple[TrustedIdentity, VerifiedRun]] = []
    repository = ""
    for identity in active:
        if identity.issuer != issuer:
            continue
        try:
            run = verified_run(identity.provider, issuer, claims)
        except IdentityMismatch as exc:
            raise Unauthorized(str(exc)) from exc
        repository = run.repository
        if same_repository(identity, run):
            matches.append((identity, run))
    if not matches:
        raise Forbidden(f"No trusted identity matches repository {repository or '(unknown)'}")
    if len({identity.project_id for identity, _ in matches}) > 1:
        reference = (project_reference or "").strip()
        if not reference:
            raise Conflict("Several projects trust this repository; pass the project name or ID")
        matches = [
            (identity, run)
            for identity, run in matches
            if _project_matches(get_project(db, identity.project_id), reference)
        ]
        if not matches:
            raise Forbidden(f"Project {reference} does not trust repository {repository}")
    granted: list[tuple[Access, TrustedIdentity, VerifiedRun]] = []
    errors = []
    for identity, run in matches:
        try:
            granted.append((access_for(identity, run), identity, run))
        except IdentityMismatch as exc:
            errors.append(str(exc))
    if not granted:
        raise Forbidden(errors[0])
    # Several bindings may cover one repository, such as a checks-only one for another workflow.
    access, identity, run = min(granted, key=lambda entry: (entry[0] != "monitor", entry[1].id))
    lock_writes(db)
    # The owner may have removed the identity while the token was being verified.
    db.refresh(identity)
    if identity.disabled_at is not None:
        raise Unauthorized("This trusted identity was removed")
    project = get_project(db, identity.project_id)
    secret = generate_token()
    now = utcnow()
    token = ApiToken(
        name=f"{run.repository} · run {run.run_id}"[:100],
        token_hash=digest(secret),
        display_prefix=secret[:DISPLAY_LENGTH],
        scopes=MONITOR_SCOPES if access == "monitor" else CHECK_SCOPES,
        project_id=project.id,
        expires_at=now + TOKEN_LIFETIME,
        kind="identity",
        identity_id=identity.id,
        claims=run.to_json(),
    )
    identity.last_used_at = now
    db.add(token)
    db.commit()
    return token, secret, access, project, run
