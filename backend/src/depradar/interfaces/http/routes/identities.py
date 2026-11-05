"""Trusted CI identities: repositories whose OIDC-verified runs may act for a project."""

from uuid import UUID

from fastapi import APIRouter, Depends

from depradar.application import identities
from depradar.domain.entities import TrustedIdentity
from depradar.interfaces.http.dependencies import Config, Db, require_session
from depradar.interfaces.http.schemas import IdentitiesOutput, IdentityInput, IdentityOutput

router = APIRouter(prefix="/api/identities", dependencies=[Depends(require_session)])


@router.get("", response_model=IdentitiesOutput)
def list_identities(db: Db, settings: Config) -> IdentitiesOutput:
    return IdentitiesOutput(
        audience=identities.audience(settings),
        identities=[IdentityOutput.model_validate(row) for row in identities.list_identities(db)],
    )


@router.post("", response_model=IdentityOutput, status_code=201)
def create_identity(body: IdentityInput, db: Db) -> TrustedIdentity:
    return identities.create_identity(
        db,
        str(body.project_id),
        body.provider,
        body.repository,
        name=body.name,
        issuer=body.issuer,
        repository_id=body.repository_id,
        workflow=body.workflow,
        monitor_ref=body.monitor_ref,
    )


@router.delete("/{identity_id}", status_code=204)
def disable_identity(identity_id: UUID, db: Db) -> None:
    """Stop trusting the identity; its outstanding short-lived tokens are revoked."""
    identities.disable_identity(db, str(identity_id))
