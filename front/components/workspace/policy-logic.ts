// Pure logic for central policies, recorded gate decisions, and trusted CI identities.
// No React and no "@/" imports, so `node --test` can load it directly.
import type { DecisionActor, DecisionMode, DecisionSummary, GatePolicy, GateStatus, IdentityProvider, PolicyAdjustment, PolicyRules, PolicySource, ReportFormat, Threshold, TrustedIdentity } from "../../lib/api.ts";

// ── Rules and strictness ─────────────────────────────────────────────────────

export const THRESHOLDS: readonly Threshold[] = ["none", "low", "medium", "high", "critical"];

/** No central requirements: what an installation that never saved a policy enforces. */
export const DEFAULT_RULES: PolicyRules = {
  fail_on: "none",
  fail_on_unknown: false,
  fail_on_kev: false,
  epss_threshold: null,
  fail_on_incomplete: false,
  require_monitored_manifests: false,
  allow_new_only: true,
  allow_ignore_acknowledged: true,
};

/** Rules that are stricter when on. The `allow_*` rules are stricter when off. */
export const REQUIRE_RULES = ["fail_on_unknown", "fail_on_kev", "fail_on_incomplete", "require_monitored_manifests"] as const;
export const ALLOW_RULES = ["allow_new_only", "allow_ignore_acknowledged"] as const;
export type RequireRule = (typeof REQUIRE_RULES)[number];
export type AllowRule = (typeof ALLOW_RULES)[number];

/**
 * How strict a severity threshold is: a lower threshold fails on more findings.
 * none 0 < critical 1 < high 2 < medium 3 < low 4.
 */
export function thresholdStrictness(value: Threshold): number {
  return value === "none" ? 0 : THRESHOLDS.length - THRESHOLDS.indexOf(value);
}

export function stricterThreshold(a: Threshold, b: Threshold): Threshold {
  return thresholdStrictness(b) > thresholdStrictness(a) ? b : a;
}

/** A lower EPSS threshold is stricter; null means no EPSS requirement. */
export function stricterEpss(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return Math.min(a, b);
}

/** The effective minimum of two layers. Layers only ever tighten, so the strictest value of each rule wins. */
export function mergeRules(base: PolicyRules, override: PolicyRules | null): PolicyRules {
  if (!override) return { ...base };
  return {
    fail_on: stricterThreshold(base.fail_on, override.fail_on),
    fail_on_unknown: base.fail_on_unknown || override.fail_on_unknown,
    fail_on_kev: base.fail_on_kev || override.fail_on_kev,
    epss_threshold: stricterEpss(base.epss_threshold, override.epss_threshold),
    fail_on_incomplete: base.fail_on_incomplete || override.fail_on_incomplete,
    require_monitored_manifests: base.require_monitored_manifests || override.require_monitored_manifests,
    allow_new_only: base.allow_new_only && override.allow_new_only,
    allow_ignore_acknowledged: base.allow_ignore_acknowledged && override.allow_ignore_acknowledged,
  };
}

/** Fills rules a client or an older API left out with the permissive defaults. */
export function normalizeRules(value: Partial<PolicyRules> | null | undefined): PolicyRules {
  return { ...DEFAULT_RULES, ...(value ?? {}) };
}

export function rulesEqual(a: PolicyRules | null, b: PolicyRules | null): boolean {
  if (a === null || b === null) return a === b;
  return (Object.keys(DEFAULT_RULES) as (keyof PolicyRules)[]).every((key) => a[key] === b[key]);
}

export function isPermissive(rules: PolicyRules): boolean {
  return rulesEqual(normalizeRules(rules), DEFAULT_RULES);
}

/** What the installation floor forces when editing a project policy: locked rules cannot be relaxed. */
export type FloorLocks = Record<RequireRule | AllowRule, boolean> & { epss: boolean; epssMax: number | null; thresholds: Threshold[] };

export function floorLocks(floor: PolicyRules): FloorLocks {
  return {
    fail_on_unknown: floor.fail_on_unknown,
    fail_on_kev: floor.fail_on_kev,
    fail_on_incomplete: floor.fail_on_incomplete,
    require_monitored_manifests: floor.require_monitored_manifests,
    allow_new_only: !floor.allow_new_only,
    allow_ignore_acknowledged: !floor.allow_ignore_acknowledged,
    epss: floor.epss_threshold !== null,
    epssMax: floor.epss_threshold,
    // Severity options weaker than the floor's threshold are unavailable.
    thresholds: THRESHOLDS.filter((option) => thresholdStrictness(option) < thresholdStrictness(floor.fail_on)),
  };
}

/** Null when the EPSS value is acceptable, otherwise the problem to show next to the field. */
export function epssProblem(value: number | null, max: number | null = null): string | null {
  if (value === null) return null;
  if (!Number.isFinite(value) || value < 0 || value > 1) return "Enter a probability between 0 and 1.";
  if (max !== null && value > max) return `Must be ${max} or lower: the installation policy already requires ${max}.`;
  return null;
}

// ── Labels ───────────────────────────────────────────────────────────────────

const capitalize = (value: string) => value ? value[0].toUpperCase() + value.slice(1) : value;

export const THRESHOLD_LABEL: Record<Threshold, string> = { none: "None", low: "Low", medium: "Medium", high: "High", critical: "Critical" };

export function thresholdText(value: Threshold): string {
  if (value === "none") return "No severity minimum";
  return value === "critical" ? "Critical only" : `${capitalize(value)} and above`;
}

/** "High and above · KEV · complete coverage": a one-line reading of a rule set. */
export function summarizeRules(rules: PolicyRules): string {
  const value = normalizeRules(rules);
  const parts: string[] = [];
  if (value.fail_on !== "none") parts.push(thresholdText(value.fail_on));
  if (value.fail_on_unknown && value.fail_on !== "none") parts.push("unknown severity");
  if (value.fail_on_kev) parts.push("KEV");
  if (value.epss_threshold !== null) parts.push(`EPSS ≥ ${value.epss_threshold}`);
  if (value.fail_on_incomplete) parts.push("complete coverage");
  if (value.require_monitored_manifests) parts.push("every manifest");
  if (!value.allow_new_only) parts.push("no new-only");
  if (!value.allow_ignore_acknowledged) parts.push("acknowledged still fail");
  if (!parts.length) return "No central requirements";
  return [capitalize(parts[0]), ...parts.slice(1)].join(" · ");
}

/** Readable names for both owner rules and the gate policy keys a decision reports. */
export const RULE_LABEL: Record<string, string> = {
  fail_on: "minimum severity",
  fail_on_unknown: "unknown severity",
  fail_on_kev: "known exploited (KEV)",
  epss_threshold: "EPSS threshold",
  fail_on_incomplete: "complete coverage",
  require_monitored_manifests: "every monitored manifest",
  allow_new_only: "new-only gating",
  new_only: "new-only gating",
  allow_ignore_acknowledged: "ignoring acknowledged findings",
  ignore_acknowledged: "ignoring acknowledged findings",
};

export const ruleLabel = (rule: string) => RULE_LABEL[rule] ?? rule.replaceAll("_", " ");

function ruleValue(key: keyof PolicyRules, rules: PolicyRules): string {
  const value = rules[key];
  if (key === "fail_on") return THRESHOLD_LABEL[value as Threshold].toLowerCase();
  if (key === "epss_threshold") return value === null ? "off" : String(value);
  if (key === "allow_new_only" || key === "allow_ignore_acknowledged") return value ? "allowed" : "not allowed";
  return value ? "on" : "off";
}

/** What changed between two versions, as "minimum severity: none → high". Null means no override. */
export function describeChanges(previous: PolicyRules | null, next: PolicyRules | null): string[] {
  if (!next) return previous ? ["Override removed; the installation policy applies"] : [];
  const before = previous ?? DEFAULT_RULES;
  const changes = (Object.keys(DEFAULT_RULES) as (keyof PolicyRules)[])
    .filter((key) => before[key] !== next[key])
    .map((key) => `${capitalize(ruleLabel(key))}: ${ruleValue(key, before)} → ${ruleValue(key, next)}`);
  return changes.length ? changes : [previous ? "No rule changes" : "Saved with no requirements"];
}

/** The pipeline's requested gate as readable rules, for showing what a decision enforced. */
export function summarizeGate(policy: GatePolicy): string {
  const parts = [thresholdText(policy.fail_on)];
  if (policy.fail_on_unknown && policy.fail_on !== "none") parts.push("unknown severity");
  if (policy.fail_on_kev) parts.push("KEV");
  if (policy.epss_threshold !== null) parts.push(`EPSS ≥ ${policy.epss_threshold}`);
  if (policy.fail_on_incomplete) parts.push("complete coverage");
  if (policy.require_monitored_manifests) parts.push("every manifest");
  parts.push(policy.new_only ? "new findings only" : "all open findings");
  if (policy.ignore_acknowledged) parts.push("acknowledged ignored");
  return parts.join(" · ");
}

export function adjustmentParts(adjustment: PolicyAdjustment) {
  return { rule: capitalize(ruleLabel(adjustment.rule)), requested: adjustment.requested, enforced: adjustment.enforced, source: adjustment.source };
}

// ── Decisions ────────────────────────────────────────────────────────────────

export const STATUS_LABEL: Record<GateStatus, string> = { pass: "Passed", fail: "Failed", error: "Error" };
export const STATUS_TONE: Record<GateStatus, string> = { pass: "dot-ok", fail: "dot-bad", error: "dot-warn" };
export const STATUS_TAG: Record<GateStatus, string> = { pass: "tag-ok", fail: "tag-bad", error: "tag-warn" };
export const MODE_LABEL: Record<DecisionMode, string> = { check: "Check", monitor: "Monitor", mixed: "Mixed" };

export function providerName(provider: string | null | undefined): string {
  if (provider === "github") return "GitHub";
  if (provider === "gitlab") return "GitLab";
  return provider ? capitalize(provider) : "CI";
}

/** Who asked for the decision: a token's name, the owner, or the verified repository. */
export function actorLabel(actor: DecisionActor): string {
  if (actor.kind === "owner") return "Owner";
  if (actor.kind === "identity" && actor.repository) return `${providerName(actor.provider)} · ${actor.repository}`;
  return actor.name || "API token";
}

export const shortSha = (sha: string | null | undefined, length = 12) => (sha ? sha.slice(0, length) : "");

/** The revision label pipelines send ("main@abc123def456"), or the short verified commit. */
export function revisionLabel(decision: Pick<DecisionSummary, "revision" | "commit">): string {
  return decision.revision || shortSha(decision.commit) || "—";
}

/** "refs/heads/main" → "main", "refs/pull/12/merge" → "PR #12", "refs/tags/v1" → "tag v1". */
export function refLabel(ref: string | null | undefined): string {
  if (!ref) return "—";
  const pull = /^refs\/pull\/(\d+)\//.exec(ref);
  if (pull) return `PR #${pull[1]}`;
  if (ref.startsWith("refs/heads/")) return ref.slice("refs/heads/".length);
  if (ref.startsWith("refs/tags/")) return `tag ${ref.slice("refs/tags/".length)}`;
  return ref;
}

const EVENTS: Record<string, string> = {
  push: "Push",
  pull_request: "Pull request",
  pull_request_target: "Pull request (target)",
  merge_group: "Merge queue",
  merge_request_event: "Merge request",
  schedule: "Schedule",
  workflow_dispatch: "Manual run",
  web: "Manual run",
  api: "API trigger",
  trigger: "Trigger",
};

export const eventLabel = (event: string | null | undefined) => (event ? EVENTS[event] ?? capitalize(event.replaceAll("_", " ")) : "—");

/** "Installation v3 · Project v1"; version 0 means the installation never saved a policy. */
export function policyLabel(sources: PolicySource[]): string {
  if (!sources.length) return "Pipeline only";
  return sources
    .slice()
    .sort((a, b) => (a.scope === b.scope ? 0 : a.scope === "installation" ? -1 : 1))
    .map((source) => (source.scope === "installation" ? (source.version ? `Installation v${source.version}` : "Installation default") : `Project v${source.version}`))
    .join(" · ");
}

export function matchesDecision(decision: DecisionSummary, query: string): boolean {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const text = [decision.project_name, decision.revision ?? "", decision.commit ?? "", actorLabel(decision.actor), decision.actor.name, decision.actor.repository ?? "", decision.actor.workflow ?? "", decision.actor.ref ?? ""].join(" ").toLowerCase();
  return terms.every((term) => text.includes(term));
}

export type StatusFilter = "all" | GateStatus;

export function statusCounts(rows: DecisionSummary[]): Record<StatusFilter, number> {
  const counts: Record<StatusFilter, number> = { all: rows.length, pass: 0, fail: 0, error: 0 };
  for (const row of rows) counts[row.status] += 1;
  return counts;
}

/** "3 violations · 1 manifest missing", or a pass or error note. Ignored findings are reported apart. */
export function outcomeText(decision: Pick<DecisionSummary, "status" | "violations" | "missing_manifests">): string {
  const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
  const parts: string[] = [];
  if (decision.violations) parts.push(plural(decision.violations, "violation"));
  if (decision.missing_manifests) parts.push(`${plural(decision.missing_manifests, "manifest")} missing`);
  if (!parts.length) parts.push(decision.status === "error" ? "Could not evaluate" : "No violations");
  return parts.join(" · ");
}

/** How old the KEV and EPSS cache was when the decision was made; stale data weakens KEV rules. */
export function intelligenceAge(decidedAt: string, refreshedAt: string | null): string {
  if (!refreshedAt) return "KEV and EPSS data had not been refreshed yet when this decision was made.";
  const hours = Math.max(0, Date.parse(decidedAt) - Date.parse(refreshedAt)) / 3_600_000;
  const age = hours < 1 ? "under an hour" : hours < 48 ? `${Math.floor(hours)} hours` : `${Math.floor(hours / 24)} days`;
  return `KEV and EPSS data were ${age} old when this decision was made.`;
}

const REPORT_EXTENSION: Record<ReportFormat, string> = { sarif: "sarif", junit: "xml", markdown: "md" };
const REPORT_TYPE: Record<ReportFormat, string> = { sarif: "application/sarif+json", junit: "application/xml", markdown: "text/markdown" };

export function reportFile(decisionId: string, format: ReportFormat) {
  return { name: `depradar-${decisionId.slice(0, 8)}.${REPORT_EXTENSION[format]}`, type: REPORT_TYPE[format] };
}

// ── Trusted identities ───────────────────────────────────────────────────────

export const DEFAULT_ISSUER: Record<IdentityProvider, string> = {
  github: "https://token.actions.githubusercontent.com",
  gitlab: "https://gitlab.com",
};

export const WORKFLOW_PLACEHOLDER: Record<IdentityProvider, string> = {
  github: ".github/workflows/depradar.yml",
  gitlab: ".gitlab-ci.yml",
};

export const REPOSITORY_PLACEHOLDER: Record<IdentityProvider, string> = {
  github: "acme/storefront",
  gitlab: "acme/web/storefront",
};

/** "main" → "refs/heads/main"; full refs and empty input pass through. */
export function normalizeRef(value: string): string | null {
  const ref = value.trim();
  if (!ref) return null;
  return ref.startsWith("refs/") ? ref : `refs/heads/${ref}`;
}

/** Null when the repository path is acceptable for the provider. */
export function repositoryProblem(provider: IdentityProvider, value: string): string | null {
  const path = value.trim();
  if (!path) return "Enter the repository path.";
  const segments = path.split("/");
  if (segments.some((segment) => !/^[A-Za-z0-9_.-]+$/.test(segment))) return "Use the path as it appears in the repository URL, without spaces or a host name.";
  if (provider === "github" && segments.length !== 2) return "GitHub repositories are owner/name.";
  if (provider === "gitlab" && segments.length < 2) return "GitLab projects are group/project, with any subgroups in between.";
  return null;
}

export const monitorLabel = (ref: string | null) => (ref ? refLabel(ref) : "Checks only");
export const identityState = (identity: Pick<TrustedIdentity, "disabled_at">) => (identity.disabled_at ? "Disabled" : "Active");

export function githubSnippet(url: string): string {
  return [
    "jobs:",
    "  dependencies:",
    "    runs-on: ubuntu-latest",
    "    permissions:",
    "      contents: read",
    "      id-token: write",
    "    steps:",
    "      - uses: actions/checkout@v5",
    "      - uses: <org>/depradar/integrations/github-action@<commit-sha>",
    "        with:",
    `          url: ${url}`,
    "          auth: oidc",
  ].join("\n");
}

export function gitlabSnippet(url: string, audience: string): string {
  return [
    "include:",
    '  - remote: "https://<host>/<path>/integrations/gitlab/depradar.gitlab-ci.yml"',
    "    inputs:",
    `      url: "${url}"`,
    "",
    "depradar-gate:",
    "  id_tokens:",
    "    DEPRADAR_ID_TOKEN:",
    `      aud: "${audience}"`,
  ].join("\n");
}
