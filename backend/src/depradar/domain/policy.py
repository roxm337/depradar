"""Central security policies: owner-defined minimums that pipelines may tighten but never relax.

The effective gate policy is the strictest of the pipeline's request, the installation minimum,
and the project minimum. Each layer only tightens, so the order of application only decides which
source is credited for a change, never the outcome.
"""

from pydantic import BaseModel, ConfigDict, Field

from depradar.domain.gate import (
    LEVELS,
    GatePolicy,
    PolicyAdjustment,
    PolicySource,
    Threshold,
)


class PolicyRules(BaseModel):
    """The owner's minimum. Defaults are permissive: no central requirement at all."""

    model_config = ConfigDict(extra="forbid")
    fail_on: Threshold = Field(
        default="none", description="Severity and above that always fails; none sets no minimum."
    )
    fail_on_unknown: bool = Field(
        default=False, description="Advisories without a severity always fail."
    )
    fail_on_kev: bool = Field(default=False, description="CISA KEV-listed CVEs always fail.")
    epss_threshold: float | None = Field(
        default=None, ge=0, le=1, description="EPSS probability that always fails."
    )
    fail_on_incomplete: bool = Field(
        default=False, description="Partial scanner coverage always fails."
    )
    require_monitored_manifests: bool = Field(
        default=False,
        description="Every monitored manifest of the project must be part of the decision.",
    )
    allow_new_only: bool = Field(
        default=True, description="Pipelines may ignore findings already open in the project."
    )
    allow_ignore_acknowledged: bool = Field(
        default=True, description="Pipelines may ignore findings the owner acknowledged."
    )


def _strictness(threshold: str) -> int:
    """Higher is stricter: critical 1, high 2, medium 3, low 4; none is the least strict."""
    return 0 if threshold == "none" else len(LEVELS) - LEVELS.index(threshold)


def _shown(value: object) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if value is None:
        return "off"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def tighten(
    policy: GatePolicy, rules: PolicyRules, source: PolicySource
) -> tuple[GatePolicy, list[PolicyAdjustment]]:
    """Apply one minimum to a policy. The result is never less strict than either input."""
    changes: dict[str, object] = {}
    if _strictness(rules.fail_on) > _strictness(policy.fail_on):
        changes["fail_on"] = rules.fail_on
    for rule in ("fail_on_unknown", "fail_on_kev", "fail_on_incomplete"):
        if getattr(rules, rule) and not getattr(policy, rule):
            changes[rule] = True
    if rules.require_monitored_manifests and not policy.require_monitored_manifests:
        changes["require_monitored_manifests"] = True
    if rules.epss_threshold is not None and (
        policy.epss_threshold is None or policy.epss_threshold > rules.epss_threshold
    ):
        changes["epss_threshold"] = rules.epss_threshold
    if policy.new_only and not rules.allow_new_only:
        changes["new_only"] = False
    if policy.ignore_acknowledged and not rules.allow_ignore_acknowledged:
        changes["ignore_acknowledged"] = False
    adjustments = [
        PolicyAdjustment(
            rule=rule,
            requested=_shown(getattr(policy, rule)),
            enforced=_shown(value),
            source=source.label(),
        )
        for rule, value in changes.items()
    ]
    return policy.model_copy(update=changes), adjustments


def enforce(
    requested: GatePolicy, minimums: list[tuple[PolicySource, PolicyRules]]
) -> tuple[GatePolicy, list[PolicyAdjustment]]:
    """The effective policy for a request, and every adjustment the minimums made to it."""
    policy, adjustments = requested, []
    for source, rules in minimums:
        policy, changed = tighten(policy, rules, source)
        adjustments += changed
    return policy, adjustments


def combine(floor: PolicyRules, rules: PolicyRules) -> PolicyRules:
    """The minimum a project's pipelines get: the stricter of two rule sets, rule by rule."""
    epss = [value for value in (floor.epss_threshold, rules.epss_threshold) if value is not None]
    return PolicyRules(
        fail_on=max(floor.fail_on, rules.fail_on, key=_strictness),
        fail_on_unknown=floor.fail_on_unknown or rules.fail_on_unknown,
        fail_on_kev=floor.fail_on_kev or rules.fail_on_kev,
        epss_threshold=min(epss) if epss else None,
        fail_on_incomplete=floor.fail_on_incomplete or rules.fail_on_incomplete,
        require_monitored_manifests=floor.require_monitored_manifests
        or rules.require_monitored_manifests,
        allow_new_only=floor.allow_new_only and rules.allow_new_only,
        allow_ignore_acknowledged=floor.allow_ignore_acknowledged
        and rules.allow_ignore_acknowledged,
    )
