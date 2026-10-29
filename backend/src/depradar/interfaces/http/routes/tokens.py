"""Scoped API tokens for CI/CD pipelines and other automation."""

from uuid import UUID

from fastapi import APIRouter, Depends

from depradar.application import auth
from depradar.domain.entities import ApiToken
from depradar.interfaces.http.dependencies import Db, require_session
from depradar.interfaces.http.schemas import CreatedTokenOutput, TokenInput, TokenOutput

router = APIRouter(prefix="/api/tokens", dependencies=[Depends(require_session)])


@router.get("", response_model=list[TokenOutput])
def list_tokens(db: Db) -> list[ApiToken]:
    return auth.list_tokens(db)


@router.post("", response_model=CreatedTokenOutput, status_code=201)
def create_token(body: TokenInput, db: Db) -> CreatedTokenOutput:
    project_id = str(body.project_id) if body.project_id else None
    token, secret = auth.create_token(
        db, body.name, list(body.scopes), project_id, body.expires_in_days
    )
    return CreatedTokenOutput(**TokenOutput.model_validate(token).model_dump(), token=secret)


@router.delete("/{token_id}", status_code=204)
def revoke_token(token_id: UUID, db: Db) -> None:
    auth.revoke_token(db, str(token_id))
