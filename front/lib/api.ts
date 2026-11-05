export type Project = {
  id: string;
  name: string;
  description: string;
  created_at: string;
  monitoring_enabled: boolean;
  check_interval_hours: number;
  next_check_at: string | null;
  notifications_enabled: boolean;
  alert_min_severity: string | null;
};

export type Inventory = {
  id: string;
  project_id: string;
  filename: string;
  target_path: string;
  revision: string | null;
  sha256: string;
  size_bytes: number;
  created_at: string;
  kind?: "monitor" | "check";
  /** Set when the owner retired this manifest; uploading it again resumes monitoring. */
  retired_at?: string | null;
};

export type Finding = {
  id: string;
  project_id: string;
  target_filename: string;
  target_path: string;
  revision: string | null;
  ecosystem: string;
  package_name: string;
  package_version: string;
  purl: string | null;
  advisory_ids: string[];
  summary: string;
  severity: string;
  cvss_vectors: string[];
  epss_score: number | null;
  epss_percentile: number | null;
  kev_known: boolean;
  intel_updated_at: string | null;
  fixed_versions: string[];
  status: string;
  evidence: Array<Record<string, unknown>>;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  workflow_status: string;
  decision_note: string;
  risk_until: string | null;
  acknowledged_at: string | null;
};

export type Scan = {
  id: string;
  inventory_id: string;
  project_id: string;
  status: string;
  complete: boolean;
  engine_version: string | null;
  error: string | null;
  package_count: number;
  coverage_notes: string[];
  created_at: string;
  completed_at: string | null;
  mode?: "monitor" | "check";
};

export type Connector = {
  id: "email" | "telegram";
  enabled: boolean;
  verified_at: string | null;
  config: Record<string, string | number | boolean>;
  credential_configured: boolean;
};

export type Delivery = {
  id: string;
  connector_id: string;
  project_id: string | null;
  kind: string;
  status: string;
  attempts: number;
  available_at: string;
  last_error: string | null;
  provider_id: string | null;
  created_at: string;
  accepted_at: string | null;
};

export type NotificationPolicy = {
  immediate_min_severity: "low" | "medium" | "high" | "critical";
  timezone: string;
  digest_hour: number;
  include_details: boolean;
  quiet_hours_start: number | null;
  quiet_hours_end: number | null;
};

export type RetentionPolicy = {
  scan_days: number;
  delivery_days: number;
};

export type FindingDecision = {
  action: string;
  note: string;
  expires_at: string | null;
  created_at: string;
};

export type OperationsHealth = {
  database: string;
  worker: string;
  worker_heartbeat_at: string | null;
  scanner: string;
  scanner_checked_at: string | null;
  queued_jobs: number;
  running_jobs: number;
  failed_jobs: number;
  oldest_queued_job_at: string | null;
  due_projects: number;
  queued_deliveries: number;
  failed_deliveries: number;
  intelligence_updated_at: string | null;
};

export type DeliveryAttempt = {
  id: string;
  delivery_id: string;
  attempt_number: number;
  status: string;
  started_at: string;
  completed_at: string | null;
  error_code: string | null;
  provider_id: string | null;
};

export type TokenScope = "projects:read" | "projects:write" | "inventories:write" | "inventories:check" | "scans:read" | "findings:read";

export type ApiToken = {
  id: string;
  name: string;
  display_prefix: string;
  scopes: TokenScope[];
  project_id: string | null;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};

export type CreatedApiToken = ApiToken & { token: string };

// ── Central security policies ──────────────────────────────────────────────

export type Threshold = "none" | "low" | "medium" | "high" | "critical";

/** The owner's minimum. Pipelines may tighten it but never relax it. */
export type PolicyRules = {
  fail_on: Threshold;
  fail_on_unknown: boolean;
  fail_on_kev: boolean;
  epss_threshold: number | null;
  fail_on_incomplete: boolean;
  require_monitored_manifests: boolean;
  allow_new_only: boolean;
  allow_ignore_acknowledged: boolean;
};

export type PolicyVersion = {
  /** Null when the installation has never saved a policy (version 0). */
  id: string | null;
  scope: "installation" | "project";
  project_id: string | null;
  version: number;
  /** Project scope only: null means the override was cleared. */
  rules: PolicyRules | null;
  note: string;
  created_at: string | null;
};

export type ProjectPolicy = { project_id: string; policy: PolicyVersion; effective: PolicyRules };
export type Policies = { installation: PolicyVersion; projects: ProjectPolicy[] };

// ── Gate results and recorded decisions ────────────────────────────────────

export type GatePolicy = {
  fail_on: Threshold;
  fail_on_unknown: boolean;
  fail_on_kev: boolean;
  epss_threshold: number | null;
  new_only: boolean;
  ignore_acknowledged: boolean;
  fail_on_incomplete: boolean;
  require_monitored_manifests: boolean;
};

export type GateStatus = "pass" | "fail" | "error";
export type PolicySource = { scope: "installation" | "project"; project_id: string | null; version: number; policy_id: string | null };
export type PolicyAdjustment = { rule: string; requested: string; enforced: string; source: string };
export type MissingManifest = { project_id: string; project_name: string; target_path: string };

export type GateItem = {
  finding_id: string | null;
  target_path: string;
  ecosystem: string;
  package_name: string;
  package_version: string;
  purl: string | null;
  advisory_ids: string[];
  summary: string;
  severity: string;
  fixed_versions: string[];
  cvss_vectors: string[];
  kev_known: boolean;
  epss_score: number | null;
  workflow_status: string;
  new: boolean;
  outcome: "violation" | "ignored" | "below_threshold";
  reasons: string[];
};

export type ScanGate = {
  scan_id: string;
  project_id: string;
  project_name: string;
  target_path: string;
  inventory_revision: string | null;
  mode: "monitor" | "check";
  scan_status: string;
  complete: boolean;
  coverage_notes: string[];
  error: string | null;
  status: GateStatus;
  items: GateItem[];
};

export type GateResult = {
  decision_id: string | null;
  status: GateStatus;
  evaluated_at: string;
  /** The enforced policy. */
  policy: GatePolicy;
  /** What the pipeline asked for. */
  requested_policy: GatePolicy;
  policy_sources: PolicySource[];
  adjustments: PolicyAdjustment[];
  missing_manifests: MissingManifest[];
  reasons: string[];
  violations: number;
  ignored: number;
  below_threshold: number;
  scans: ScanGate[];
};

export type DecisionActor = {
  kind: "owner" | "token" | "identity";
  name: string;
  token_id: string | null;
  /** True only for OIDC-verified runs. */
  verified: boolean;
  provider: string | null;
  repository: string | null;
  workflow: string | null;
  ref: string | null;
  event: string | null;
  run_id: string | null;
  run_url: string | null;
};

export type DecisionMode = "monitor" | "check" | "mixed";

export type DecisionSummary = {
  id: string;
  created_at: string;
  status: GateStatus;
  project_id: string;
  project_name: string;
  revision: string | null;
  /** Full verified commit SHA, for OIDC runs only. */
  commit: string | null;
  mode: DecisionMode;
  violations: number;
  ignored: number;
  below_threshold: number;
  missing_manifests: number;
  actor: DecisionActor;
  policy_sources: PolicySource[];
  /** How many rules central policy enforced over the request. */
  adjustments: number;
};

export type DecisionInput = {
  scan_id: string;
  target_path: string;
  filename: string;
  mode: "monitor" | "check";
  sha256: string;
  revision: string | null;
  scan_status: string;
  complete: boolean;
  engine_version: string | null;
  completed_at: string | null;
  coverage_notes: string[];
};

export type DecisionException = {
  finding_id: string | null;
  target_path: string;
  package_name: string;
  package_version: string;
  advisory_ids: string[];
  workflow_status: string;
  reason: string;
  risk_until: string | null;
};

export type DecisionDetail = DecisionSummary & {
  inputs: DecisionInput[];
  exceptions: DecisionException[];
  intelligence_updated_at: string | null;
  result: GateResult;
};

export type ReportFormat = "sarif" | "junit" | "markdown";

// ── Trusted CI identities (OIDC) ───────────────────────────────────────────

export type IdentityProvider = "github" | "gitlab";

export type TrustedIdentity = {
  id: string;
  project_id: string;
  name: string;
  provider: IdentityProvider;
  issuer: string;
  repository: string;
  repository_id: string | null;
  /** Trusted workflow path; null accepts any workflow in the repository. */
  workflow: string | null;
  /** Branch whose runs may update monitored state; null means check-only. */
  monitor_ref: string | null;
  created_at: string;
  last_used_at: string | null;
  disabled_at: string | null;
};

export type IdentityInput = {
  project_id: string;
  name?: string;
  provider: IdentityProvider;
  issuer?: string;
  repository: string;
  repository_id?: string | null;
  workflow?: string | null;
  monitor_ref?: string | null;
};

export type Identities = { audience: string; identities: TrustedIdentity[] };

// The dashboard listens for this to send expired or revoked sessions back to the login page.
export const UNAUTHORIZED_EVENT = "depradar:unauthorized";

let csrfToken = "";

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

export function setCsrfToken(value: string) {
  csrfToken = value;
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof ArrayBuffer) && !(options.body instanceof Blob)) {
    headers.set("content-type", "application/json");
  }
  if (csrfToken && options.method && options.method !== "GET") headers.set("x-csrf-token", csrfToken);
  const response = await fetch(`/api/backend/${path.replace(/^\//, "")}`, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 204) return undefined as T;
  const payload = (await response.json().catch(() => ({}))) as T & { detail?: string };
  if (response.status === 401) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  if (!response.ok) throw new ApiError(payload.detail || `Request failed (${response.status})`, response.status);
  return payload;
}

export const json = (method: string, value: unknown): RequestInit => ({
  method,
  body: JSON.stringify(value),
});

/** A current monitored manifest, as package search covers it. */
export type ComponentSnapshot = {
  project_id: string;
  project_name: string;
  inventory_id: string;
  filename: string;
  target_path: string;
  revision: string | null;
  /** When the manifest was uploaded, not when it was deployed. */
  uploaded_at: string;
};

/** The scan whose report produced a manifest's package list. */
export type ComponentIndex = {
  scan_id: string;
  status: string;
  complete: boolean;
  completed_at: string | null;
  coverage_notes: string[];
};

export type ComponentCoverage = {
  snapshots: number;
  indexed: number;
  ecosystems: string[];
  /** Manifests without a package list yet; a recheck indexes them. */
  not_indexed: ComponentSnapshot[];
  /** Manifests indexed by an incomplete scan; a package may be missing from them. */
  partial: Array<ComponentSnapshot & { indexed_by: ComponentIndex }>;
};

export type ComponentMatch = {
  ecosystem: string;
  name: string;
  /** Empty when the manifest left the package unpinned. */
  version: string;
  purl: string | null;
  snapshot: ComponentSnapshot;
  indexed_by: ComponentIndex;
  open_findings: number;
};

export type ComponentSearch = {
  name: string;
  ecosystem: string | null;
  version: string | null;
  matches: ComponentMatch[];
  truncated: boolean;
  coverage: ComponentCoverage;
};
