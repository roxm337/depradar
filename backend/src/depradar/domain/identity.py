"""Verified CI identity: which pipeline run a signed OIDC token describes, and what it may do.

Only claims from a token whose signature, issuer, audience, and lifetime were verified reach this
module. A trusted identity binds one repository (and optionally one workflow) to one project. Runs
of the protected monitor branch, started by an ordinary push or schedule, may update monitored
state; every other run, including all pull and merge request runs, gets check-only access.
"""

from dataclasses import asdict, dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError

from depradar.domain.entities import TrustedIdentity

Provider = Literal["github", "gitlab"]
Access = Literal["monitor", "check"]
PROVIDERS: tuple[Provider, ...] = ("github", "gitlab")
DEFAULT_ISSUERS: dict[str, str] = {
    "github": "https://token.actions.githubusercontent.com",
    "gitlab": "https://gitlab.com",
}
# Events that run reviewed code from the branch itself. Pull request targets, merge queues, and
# manual triggers on other refs never qualify, because they can run unmerged changes.
MONITOR_EVENTS: dict[str, set[str]] = {
    "github": {"push", "schedule", "workflow_dispatch"},
    "gitlab": {"push", "schedule", "web"},
}
SHA = r"^[0-9a-f]{40}([0-9a-f]{24})?$"


class IdentityMismatch(Exception):
    """The verified run is not allowed to act as the trusted identity; the text is safe to show."""


def _text(value: Any) -> Any:
    # GitHub and GitLab encode numeric identifiers inconsistently across versions.
    return str(value) if isinstance(value, int) and not isinstance(value, bool) else value


Text = Annotated[str, BeforeValidator(_text)]


class GitHubClaims(BaseModel):
    model_config = ConfigDict(extra="ignore")
    repository: Text = Field(min_length=3, max_length=200)
    repository_id: Text = Field(min_length=1, max_length=40)
    ref: Text = Field(default="", max_length=300)
    ref_type: Text = Field(default="", max_length=20)
    sha: Text = Field(pattern=SHA)
    workflow_ref: Text = Field(default="", max_length=600)
    event_name: Text = Field(min_length=1, max_length=60)
    run_id: Text = Field(min_length=1, max_length=40)
    actor: Text = Field(default="", max_length=100)
    head_ref: Text = Field(default="", max_length=300)
    environment: Text | None = Field(default=None, max_length=200)


class GitLabClaims(BaseModel):
    model_config = ConfigDict(extra="ignore")
    project_path: Text = Field(min_length=3, max_length=300)
    project_id: Text = Field(min_length=1, max_length=40)
    ref: Text = Field(default="", max_length=300)
    ref_type: Text = Field(default="", max_length=20)
    ref_protected: Text = Field(default="false", max_length=10)
    sha: Text = Field(pattern=SHA)
    ci_config_ref_uri: Text = Field(default="", max_length=800)
    pipeline_source: Text = Field(min_length=1, max_length=60)
    pipeline_id: Text = Field(min_length=1, max_length=40)
    job_id: Text = Field(default="", max_length=40)
    user_login: Text = Field(default="", max_length=100)
    environment: Text | None = Field(default=None, max_length=200)


@dataclass(frozen=True)
class VerifiedRun:
    """The facts a verified OIDC token establishes about one CI run."""

    provider: str
    issuer: str
    repository: str
    repository_id: str
    workflow: str
    ref: str
    ref_type: str
    sha: str
    event: str
    protected: bool | None
    run_id: str
    run_url: str
    actor: str
    environment: str | None
    head_ref: str = ""

    @property
    def ref_name(self) -> str:
        for prefix in ("refs/heads/", "refs/tags/"):
            if self.ref.startswith(prefix):
                return self.ref[len(prefix) :]
        return self.ref

    def revision(self) -> str:
        """Branch@commit label matching what the CI client reports for unverified runs."""
        return f"{self.head_ref or self.ref_name}@{self.sha[:12]}"[:200]

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, value: dict[str, Any] | None) -> "VerifiedRun | None":
        """The run stored with an exchanged token; None when the record is unusable."""
        if not isinstance(value, dict):
            return None
        try:
            return cls(**{key: value[key] for key in cls.__dataclass_fields__ if key in value})
        except TypeError:
            return None


def _workflow_path(reference: str, prefix: str) -> str:
    """The file path in `<prefix><path>@refs/...`, or "" when the reference has another shape."""
    if not reference.lower().startswith(prefix.lower()):
        return ""
    path, separator, _ = reference[len(prefix) :].partition("@refs/")
    return path.strip("/") if separator else ""


def _web_origin(issuer: str) -> str:
    # github.com signs with a dedicated host; GitHub Enterprise Server uses /_services/token.
    if issuer == DEFAULT_ISSUERS["github"]:
        return "https://github.com"
    return issuer.removesuffix("/_services/token").rstrip("/")


def verified_run(provider: str, issuer: str, claims: dict[str, Any]) -> VerifiedRun:
    """Normalize verified claims. Raises IdentityMismatch when required claims are missing."""
    try:
        if provider == "github":
            github = GitHubClaims.model_validate(claims)
            origin = _web_origin(issuer)
            return VerifiedRun(
                provider="github",
                issuer=issuer,
                repository=github.repository,
                repository_id=github.repository_id,
                workflow=_workflow_path(github.workflow_ref, github.repository + "/"),
                ref=github.ref,
                ref_type=github.ref_type,
                sha=github.sha,
                event=github.event_name,
                protected=None,
                run_id=github.run_id,
                run_url=f"{origin}/{github.repository}/actions/runs/{github.run_id}",
                actor=github.actor,
                environment=github.environment,
                head_ref=github.head_ref,
            )
        if provider == "gitlab":
            gitlab = GitLabClaims.model_validate(claims)
            kind = {"branch": "refs/heads/", "tag": "refs/tags/"}.get(gitlab.ref_type, "")
            host, project = issuer.split("://", 1)[-1].rstrip("/"), gitlab.project_path
            page = f"jobs/{gitlab.job_id}" if gitlab.job_id else f"pipelines/{gitlab.pipeline_id}"
            return VerifiedRun(
                provider="gitlab",
                issuer=issuer,
                repository=gitlab.project_path,
                repository_id=gitlab.project_id,
                workflow=_workflow_path(gitlab.ci_config_ref_uri, f"{host}/{project}//"),
                ref=kind + gitlab.ref if kind else gitlab.ref,
                ref_type=gitlab.ref_type,
                sha=gitlab.sha,
                event=gitlab.pipeline_source,
                protected=gitlab.ref_protected == "true",
                run_id=gitlab.pipeline_id,
                run_url=f"{issuer.rstrip('/')}/{gitlab.project_path}/-/{page}",
                actor=gitlab.user_login,
                environment=gitlab.environment,
            )
    except ValidationError as exc:
        fields = sorted({".".join(str(part) for part in error["loc"]) for error in exc.errors()})
        message = "The identity token lacks valid claims: " + ", ".join(fields)
        raise IdentityMismatch(message) from exc
    raise IdentityMismatch("Unsupported identity provider")


def same_repository(identity: TrustedIdentity, run: VerifiedRun) -> bool:
    """Repository IDs are immutable, so a deleted and re-created namesake cannot match."""
    if identity.provider != run.provider or identity.issuer != run.issuer:
        return False
    if identity.repository_id and identity.repository_id != run.repository_id:
        return False
    return identity.repository.lower() == run.repository.lower()


def access_for(identity: TrustedIdentity, run: VerifiedRun) -> Access:
    """What a run of a matching repository may do. Raises IdentityMismatch for other workflows."""
    if identity.workflow and identity.workflow != run.workflow:
        raise IdentityMismatch(
            f"Workflow {run.workflow or '(unknown)'} is not the trusted workflow for "
            f"{identity.repository}"
        )
    monitor = (
        identity.monitor_ref is not None
        and run.ref == identity.monitor_ref
        and run.ref_type == "branch"
        and run.event in MONITOR_EVENTS.get(run.provider, set())
        # GitLab states whether the branch is protected; GitHub relies on branch protection.
        and run.protected is not False
    )
    return "monitor" if monitor else "check"


def canonical_ref(value: str | None) -> str | None:
    """Accept `main` or `refs/heads/main` for a monitor branch."""
    if value is None or not value.strip():
        return None
    value = value.strip()
    return value if value.startswith("refs/") else "refs/heads/" + value


def canonical_workflow(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip().removeprefix("./").strip("/")
