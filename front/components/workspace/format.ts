import type { ApiToken, Finding, Inventory, Project, Scan } from "@/lib/api";

export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityOf(value: string): Severity {
  const normalized = value.toLowerCase();
  return (SEVERITIES as readonly string[]).includes(normalized) ? (normalized as Severity) : "unknown";
}

export const severityRank = (value: string) => SEVERITIES.length - SEVERITIES.indexOf(severityOf(value));

// Priority: severity, then known exploitation, then exploit probability, then recency.
export function byPriority(a: Finding, b: Finding) {
  return severityRank(b.severity) - severityRank(a.severity)
    || Number(b.kev_known) - Number(a.kev_known)
    || (b.epss_score ?? -1) - (a.epss_score ?? -1)
    || Date.parse(b.first_seen_at) - Date.parse(a.first_seen_at);
}

export function countBySeverity(findings: Finding[]) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const finding of findings) counts[severityOf(finding.severity)] += 1;
  return counts;
}

export function relativeTime(now: number, value: string | null | undefined) {
  if (!value || !now) return "—";
  const diff = now - Date.parse(value);
  // The clock ticks every 30 s, so fresh server timestamps can sit slightly ahead of it.
  if (Math.abs(diff) < 60_000) return "just now";
  const seconds = Math.abs(diff) / 1000;
  const label = seconds < 3600 ? `${Math.floor(seconds / 60)}m` : seconds < 86_400 ? `${Math.floor(seconds / 3600)}h` : `${Math.floor(seconds / 86_400)}d`;
  return diff < 0 ? `in ${label}` : `${label} ago`;
}

export function shortDate(value: string | null | undefined) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" }).format(new Date(value));
}

export function dateTime(value: string | null | undefined) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

export function monogram(name: string) {
  const parts = name.split(/[\s/._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? parts[0]?.[1] ?? "")).toUpperCase();
}

export function cadence(hours: number) {
  if (hours === 1) return "hourly";
  if (hours === 24) return "daily";
  if (hours === 168) return "weekly";
  return hours % 24 === 0 ? `every ${hours / 24} days` : `every ${hours}h`;
}

export function accessLabel(scopes: string[]) {
  const key = [...scopes].sort().join(" ");
  const preset = Object.values(tokenPresets).find((value) => [...value.scopes].sort().join(" ") === key);
  return preset?.label ?? `${scopes.length} custom scope${scopes.length === 1 ? "" : "s"}`;
}

export function primaryAdvisory(ids: string[]) {
  return ids.find((id) => id.startsWith("GHSA-")) ?? ids.find((id) => id.startsWith("CVE-")) ?? ids[0] ?? "—";
}

export function latestScan(scans: Scan[], projectId: string) {
  return scans.find((scan) => scan.project_id === projectId);
}

const newestFirst = (a: { created_at: string; id: string }, b: { created_at: string; id: string }) =>
  Date.parse(b.created_at) - Date.parse(a.created_at) || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0);

/** The newest snapshot of each manifest path, retired or not, newest first. */
function newestPerTarget(inventories: Inventory[], projectId: string) {
  const current = new Map<string, Inventory>();
  for (const row of inventories.filter((inventory) => inventory.project_id === projectId).sort(newestFirst)) {
    if (!current.has(row.target_path)) current.set(row.target_path, row);
  }
  return [...current.values()];
}

/**
 * The current monitored snapshot of each manifest path, newest first. A path whose newest
 * snapshot is retired is no longer monitored; uploading it again makes a newer, active snapshot.
 */
export function latestPerTarget(inventories: Inventory[], projectId: string) {
  return newestPerTarget(inventories, projectId).filter((row) => !row.retired_at);
}

/** Manifests the owner retired, as their newest (retired) snapshot. */
export function retiredTargets(inventories: Inventory[], projectId: string) {
  return newestPerTarget(inventories, projectId).filter((row) => row.retired_at);
}

export type CoverageState = "none" | "unknown" | "unscanned" | "pending" | "incomplete" | "verified";
export type Coverage = { state: CoverageState; manifests: Inventory[]; verified: number; latest: Scan | undefined };

/**
 * Whether the latest monitor scan of every current manifest finished with complete coverage.
 * CI check scans never describe monitored state, and an empty finding list alone proves nothing.
 */
export function projectCoverage(projectId: string, inventories: Inventory[], scans: Scan[]): Coverage {
  const manifests = latestPerTarget(inventories, projectId);
  const monitorScans = scans.filter((scan) => scan.project_id === projectId && scan.mode !== "check" && scan.status !== "superseded").sort(newestFirst);
  const latest = monitorScans[0];
  // Scans without any snapshot mean the inventory list is unavailable; retired-only means none.
  const retired = retiredTargets(inventories, projectId).length > 0;
  if (!manifests.length) return { state: monitorScans.length && !retired ? "unknown" : "none", manifests, verified: 0, latest };
  const states = manifests.map((manifest) => {
    const scan = monitorScans.find((row) => row.inventory_id === manifest.id);
    if (!scan) return "unscanned";
    if (scan.status === "queued" || scan.status === "running") return "pending";
    return scan.status === "succeeded" && scan.complete ? "verified" : "incomplete";
  });
  const verified = states.filter((state) => state === "verified").length;
  const state = (["incomplete", "unscanned", "pending"] as const).find((value) => states.includes(value)) ?? "verified";
  return { state, manifests, verified, latest };
}

/** Workspace-wide coverage: verified only when every project with manifests is verified. */
export function workspaceCoverage(projects: Project[], inventories: Inventory[], scans: Scan[]): CoverageState {
  const states = projects.map((project) => projectCoverage(project.id, inventories, scans).state);
  if (!states.length || states.every((state) => state === "none")) return "none";
  return (["incomplete", "unknown", "unscanned", "pending"] as const).find((value) => states.includes(value)) ?? (states.includes("none") ? "unscanned" : "verified");
}

export const coverageLabel: Record<CoverageState, string> = {
  none: "No manifests",
  unknown: "Coverage unknown",
  unscanned: "Not scanned yet",
  pending: "Scan in progress",
  incomplete: "Incomplete coverage",
  verified: "Clear",
};

export function scanTone(scan: Scan | undefined) {
  if (!scan) return "";
  if (scan.status === "failed") return "dot-bad";
  if (scan.status === "queued" || scan.status === "running") return "dot-warn dot-live";
  if (scan.status === "partial" || !scan.complete) return "dot-warn";
  return "dot-ok";
}

export function scanLabel(scan: Scan) {
  if (scan.status === "succeeded" && !scan.complete) return "Completed with coverage gaps";
  const labels: Record<string, string> = { queued: "Queued", running: "Scanning", succeeded: "Completed", partial: "Partial coverage", failed: "Failed", superseded: "Superseded" };
  return labels[scan.status] ?? scan.status;
}

export function projectName(projects: Project[], id: string | null) {
  return projects.find((project) => project.id === id)?.name ?? (id ? "Removed project" : "All projects");
}

export const inventoryFiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "composer.lock", "poetry.lock", "uv.lock", "pylock.toml", "Pipfile.lock", "requirements.txt", "Gemfile.lock", "Cargo.lock", "go.mod", "pubspec.lock"];

export const formatGroups = [
  { label: "npm, pnpm, Yarn, Bun", files: "package-lock.json · pnpm-lock.yaml · yarn.lock · bun.lock" },
  { label: "PHP · Composer", files: "composer.lock" },
  { label: "Python", files: "poetry.lock · uv.lock · pylock.toml · Pipfile.lock · requirements*.txt" },
  { label: "Ruby · Rust · Go", files: "Gemfile.lock · Cargo.lock · go.mod" },
  { label: "Dart · Flutter", files: "pubspec.lock" },
  { label: "SBOM", files: "CycloneDX JSON 1.4–1.7 · bom.json · *.cdx.json" },
];

export function supportedInventory(name: string) {
  return inventoryFiles.includes(name) || /^requirements[\w.-]{0,100}\.txt$/.test(name) || name === "bom.json" || name.endsWith(".cdx.json");
}

export function inventoryKind(name: string) {
  if (name.endsWith(".cdx.json") || name === "bom.json") return "CycloneDX SBOM";
  if (/^requirements/.test(name)) return "pip requirements";
  const kinds: Record<string, string> = { "package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "Yarn", "bun.lock": "Bun", "composer.lock": "Composer", "poetry.lock": "Poetry", "uv.lock": "uv", "pylock.toml": "pylock", "Pipfile.lock": "Pipenv", "Gemfile.lock": "Bundler", "Cargo.lock": "Cargo", "go.mod": "Go modules", "pubspec.lock": "Pub" };
  return kinds[name] ?? "Unsupported";
}

export const tokenPresets: Record<string, { label: string; detail: string; scopes: ApiToken["scopes"] }> = {
  pipeline: { label: "Pipeline gate", detail: "Upload lockfiles, wait for scans, and evaluate the gate.", scopes: ["projects:read", "inventories:write", "scans:read", "findings:read"] },
  onboarding: { label: "Pipeline gate + onboarding", detail: "Also creates missing projects, for agency-wide templates.", scopes: ["projects:read", "projects:write", "inventories:write", "scans:read", "findings:read"] },
  reporting: { label: "Read-only reporting", detail: "Read projects, scans, and findings for dashboards and exports.", scopes: ["projects:read", "scans:read", "findings:read"] },
};

export function tokenState(token: ApiToken, now: number) {
  if (token.revoked_at) return "Revoked";
  return now && Date.parse(token.expires_at) <= now ? "Expired" : "Active";
}

export function bytes(size: number) {
  return size < 1024 ? `${size} B` : size < 1024 * 1024 ? `${(size / 1024).toFixed(1)} KB` : `${(size / 1024 / 1024).toFixed(1)} MB`;
}
