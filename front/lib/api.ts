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

export type TokenScope = "projects:read" | "projects:write" | "inventories:write" | "scans:read" | "findings:read";

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
