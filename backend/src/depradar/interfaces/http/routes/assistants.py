"""What AI assistants did through the MCP endpoint, for the owner to review."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from depradar.application import audit
from depradar.interfaces.http.dependencies import Config, Db, require_session
from depradar.interfaces.http.schemas import AssistantActivityOutput, AuditEventOutput

router = APIRouter(prefix="/api/mcp", dependencies=[Depends(require_session)])


@router.get("/activity", response_model=AssistantActivityOutput)
def activity(
    db: Db,
    settings: Config,
    token_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AssistantActivityOutput:
    """Recent MCP calls, newest first. Arguments and results are never recorded."""
    rows = audit.recent(db, limit, offset, str(token_id) if token_id else None)
    return AssistantActivityOutput(
        enabled=settings.mcp_enabled,
        events=[AuditEventOutput.model_validate(row) for row in rows],
    )
