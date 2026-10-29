"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, json, setCsrfToken, UNAUTHORIZED_EVENT, type ApiToken, type Connector, type CreatedApiToken, type Delivery, type DeliveryAttempt, type Finding, type FindingDecision, type Inventory, type NotificationPolicy, type OperationsHealth, type Project, type RetentionPolicy, type Scan } from "@/lib/api";
import { supportedInventory } from "@/components/workspace/format";

export type Session = "checking" | "ready" | "offline";
export type Notice = { kind: "success" | "error" | "info"; text: string } | null;
export type ModalState = { kind: "project" } | { kind: "upload"; projectId?: string } | { kind: "risk"; findingId: string } | { kind: "connector"; channel: "email" | "telegram" } | { kind: "token" } | null;
export type Filters = { status: "open" | "resolved" | "all"; severities: string[]; decision: string; project: string; sort: "priority" | "newest" | "package" };
export type EmailInput = { host: string; port: number; username: string; sender: string; recipient: string; tls_mode: string };
export type UploadInput = { projectId: string; file: File; targetPath: string; revision: string };

const defaultFilters: Filters = { status: "open", severities: [], decision: "all", project: "all", sort: "priority" };
const defaultPolicy: NotificationPolicy = { immediate_min_severity: "high", timezone: "UTC", digest_hour: 8, include_details: false, quiet_hours_start: null, quiet_hours_end: null };

async function loadAllPages<T>(fetchPage: (offset: number) => Promise<T[]>): Promise<T[]> {
  const rows: T[] = [];
  for (let offset = 0; ; offset += 100) {
    const page = await fetchPage(offset);
    rows.push(...page);
    if (page.length < 100) return rows;
  }
}

async function mapInBatches<T, R>(values: T[], size: number, task: (value: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  for (let index = 0; index < values.length; index += size) results.push(...await Promise.all(values.slice(index, index + size).map(task)));
  return results;
}

const message = (failure: unknown, fallback: string) => failure instanceof Error ? failure.message : fallback;

function useWorkspaceState() {
  const router = useRouter();
  const [session, setSession] = useState<Session>("checking");
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [upgradeHint, setUpgradeHint] = useState(false);
  const [syncedAt, setSyncedAt] = useState<string | null>(null);
  const [now, setNow] = useState(0);
  const [origin, setOrigin] = useState("");
  const [projects, setProjects] = useState<Project[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [inventories, setInventories] = useState<Inventory[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [policy, setPolicy] = useState<NotificationPolicy>(defaultPolicy);
  const [retention, setRetention] = useState<RetentionPolicy>({ scan_days: 30, delivery_days: 30 });
  const [health, setHealth] = useState<OperationsHealth | null>(null);
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [notice, setNotice] = useState<Notice>(null);
  const [modal, setModal] = useState<ModalState>(null);
  const [findingId, setFindingId] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const liveDataLoaded = useRef(false);
  const pollInFlight = useRef(false);

  const load = useCallback(async (silent = true) => {
    if (!silent) setLoading(true);
    try {
      const status = await api<{ initialized: boolean }>("auth/status");
      if (!status.initialized) { router.replace("/login"); return; }
      // A 401 raises UNAUTHORIZED_EVENT, whose listener sends the browser to the login page.
      const me = await api<{ csrf_token: string }>("auth/me");
      setCsrfToken(me.csrf_token);
      setSession("ready");
      const projectRows = await loadAllPages<Project>((offset) => api<Project[]>(`projects?limit=100&offset=${offset}`));
      const [findingRows, scanRows, inventoryRows, connectorRows, deliveryRows, policyValue, retentionValue, healthValue, tokenRows] = await Promise.all([
        mapInBatches(projectRows, 8, (project) => loadAllPages<Finding>((offset) => api<Finding[]>(`projects/${project.id}/findings?limit=100&offset=${offset}`))),
        mapInBatches(projectRows, 8, (project) => loadAllPages<Scan>((offset) => api<Scan[]>(`projects/${project.id}/scans?limit=100&offset=${offset}`))),
        mapInBatches(projectRows, 8, async (project) => {
          try { return await loadAllPages<Inventory>((offset) => api<Inventory[]>(`projects/${project.id}/inventories?limit=100&offset=${offset}`)); }
          catch (failure) { if (failure instanceof ApiError && failure.status === 405) { setUpgradeHint(true); return []; } throw failure; }
        }),
        api<Connector[]>("connectors"),
        loadAllPages<Delivery>((offset) => api<Delivery[]>(`notifications/deliveries?limit=100&offset=${offset}`)),
        api<NotificationPolicy>("notifications/policy"),
        api<RetentionPolicy>("maintenance/retention"),
        api<OperationsHealth>("operations/health").catch(() => null),
        api<ApiToken[]>("tokens").catch(() => [] as ApiToken[]),
      ]);
      setProjects(projectRows.map((project) => ({ ...project, notifications_enabled: project.notifications_enabled ?? true, alert_min_severity: project.alert_min_severity ?? null })));
      setFindings(findingRows.flat().map((finding) => ({ ...finding, target_path: finding.target_path ?? finding.target_filename, revision: finding.revision ?? null, purl: finding.purl ?? null, cvss_vectors: finding.cvss_vectors ?? [], epss_score: finding.epss_score ?? null, epss_percentile: finding.epss_percentile ?? null, kev_known: finding.kev_known ?? false, intel_updated_at: finding.intel_updated_at ?? null })));
      setScans(scanRows.flat().sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)));
      setInventories(inventoryRows.flat());
      setConnectors(connectorRows);
      setDeliveries(deliveryRows);
      setPolicy({ ...policyValue, quiet_hours_start: policyValue.quiet_hours_start ?? null, quiet_hours_end: policyValue.quiet_hours_end ?? null });
      setRetention(retentionValue);
      setHealth(healthValue);
      setTokens(tokenRows);
      setError("");
      setSyncedAt(new Date().toISOString());
      liveDataLoaded.current = true;
      setReady(true);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) return;
      setError(message(failure, "Could not load workspace data."));
      // Without a loaded workspace there is nothing to keep showing, so show the offline screen.
      setSession((current) => current === "ready" ? current : "offline");
    } finally { if (!silent) setLoading(false); }
  }, [router]);

  useEffect(() => { const timer = window.setTimeout(() => void load(false), 0); return () => window.clearTimeout(timer); }, [load]);
  useEffect(() => {
    // A full navigation discards the in-memory workspace; Next would otherwise keep it hidden.
    const signedOut = () => { setCsrfToken(""); if (liveDataLoaded.current) window.location.replace("/login?expired=1"); else router.replace("/login"); };
    window.addEventListener(UNAUTHORIZED_EVENT, signedOut);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, signedOut);
  }, [router]);
  useEffect(() => {
    const tick = () => { setNow(Date.now()); setOrigin(window.location.origin); };
    const first = window.setTimeout(tick, 0);
    const timer = window.setInterval(tick, 30_000);
    return () => { window.clearTimeout(first); window.clearInterval(timer); };
  }, []);
  useEffect(() => {
    const pendingScans = scans.filter((scan) => scan.status === "queued" || scan.status === "running");
    const pendingDelivery = deliveries.some((delivery) => delivery.status === "queued" || delivery.status === "sending");
    if (session !== "ready" || (!pendingScans.length && !pendingDelivery)) return;
    const timer = window.setInterval(() => {
      if (pollInFlight.current) return;
      pollInFlight.current = true;
      void Promise.all([
        Promise.all(pendingScans.map((scan) => api<Scan>(`scans/${scan.id}`))),
        pendingDelivery ? loadAllPages<Delivery>((offset) => api<Delivery[]>(`notifications/deliveries?limit=100&offset=${offset}`)) : Promise.resolve(null),
      ]).then(([updated, deliveryRows]) => {
        if (deliveryRows) setDeliveries(deliveryRows);
        setScans((current) => current.map((scan) => updated.find((row) => row.id === scan.id) ?? scan));
        // A finished scan can change findings and inventories, so reload everything once.
        if (updated.some((scan) => scan.status !== "queued" && scan.status !== "running")) return load();
      }).catch(() => undefined).finally(() => { pollInFlight.current = false; });
    }, 4000);
    return () => window.clearInterval(timer);
  }, [deliveries, load, scans, session]);
  useEffect(() => {
    if (session !== "ready") return;
    const timer = window.setInterval(() => { void api<OperationsHealth>("operations/health").then(setHealth).catch(() => undefined); }, 30_000);
    return () => window.clearInterval(timer);
  }, [session]);
  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 5200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const notify = useCallback((kind: "success" | "error" | "info", text: string) => setNotice({ kind, text }), []);
  const run = useCallback(async (action: () => Promise<unknown>, success: string) => {
    try { await action(); setNotice({ kind: "success", text: success }); await load(); return true; }
    catch (failure) { setNotice({ kind: "error", text: message(failure, "Something went wrong.") }); return false; }
  }, [load]);

  const actions = {
    refresh: () => load(false),
    logout: async () => {
      try { await api("auth/logout", { method: "POST" }); }
      catch (failure) { if (!(failure instanceof ApiError && failure.status === 401)) { notify("error", message(failure, "Could not sign out.")); return; } }
      setCsrfToken("");
      window.location.replace("/login?signed_out=1");
    },
    createProject: (name: string, description: string) => run(() => api("projects", json("POST", { name, description })), `Project ${name} created.`),
    deleteProject: async (project: Project) => {
      const done = await run(() => api(`projects/${project.id}`, { method: "DELETE" }), `Project ${project.name} deleted.`);
      if (done) setProjectId(null);
      return done;
    },
    uploadInventory: async ({ projectId: target, file, targetPath, revision }: UploadInput) => {
      if (!supportedInventory(file.name)) { notify("error", "This file type is not a supported lockfile or SBOM."); return false; }
      if (file.size > 10 * 1024 * 1024) { notify("error", "Inventory files must be 10 MB or smaller."); return false; }
      const params = new URLSearchParams({ filename: file.name });
      if (targetPath.trim()) params.set("target_path", targetPath.trim());
      if (revision.trim()) params.set("revision", revision.trim());
      return run(async () => api(`projects/${target}/inventories?${params}`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body: await file.arrayBuffer() }), "Inventory uploaded. The scan is queued.");
    },
    rescan: (inventoryId: string, label: string) => run(() => api(`inventories/${inventoryId}/scans`, json("POST", {})), `A fresh scan was queued for ${label}.`),
    rescanAll: (inventoryIds: string[], label: string) => run(() => Promise.all(inventoryIds.map((id) => api(`inventories/${id}/scans`, json("POST", {})))), `${inventoryIds.length} scans queued for ${label}.`),
    setMonitoring: (project: Project, enabled: boolean, hours: number) => run(() => api(`projects/${project.id}/monitoring`, json("PUT", { enabled, interval_hours: hours })), enabled ? `Monitoring ${project.name} every ${hours}h.` : `Monitoring paused for ${project.name}.`),
    setAlerts: (project: Project, enabled: boolean, threshold: string) => run(() => api(`projects/${project.id}/notifications`, json("PUT", { enabled, immediate_min_severity: threshold })), `Alert settings saved for ${project.name}.`),
    acknowledge: (finding: Finding) => run(() => api(`findings/${finding.id}/acknowledge`, json("POST", { note: "" })), `${finding.package_name} acknowledged.`),
    acceptRisk: (finding: Finding, reason: string, expiresAt: string) => run(() => api(`findings/${finding.id}/risk-acceptance`, json("POST", { reason, expires_at: expiresAt })), "Risk acceptance recorded."),
    clearDecision: (finding: Finding) => run(() => api(finding.workflow_status === "risk_accepted" ? `findings/${finding.id}/risk-acceptance` : `findings/${finding.id}/acknowledge`, { method: "DELETE" }), "Decision cleared; the finding needs review again."),
    loadDecisions: (id: string) => api<FindingDecision[]>(`findings/${id}/decisions`),
    configureEmail: async (input: EmailInput) => {
      try { await api("connectors/email", json("PUT", { ...input, enabled: true })); notify("success", "Verification code sent. Check the recipient inbox."); return true; }
      catch (failure) { notify("error", message(failure, "Could not configure email.")); return false; }
    },
    verifyEmail: (code: string) => run(() => api("connectors/email/verify", json("POST", { code })), "Email destination verified."),
    pairTelegram: async () => {
      try { return (await api<{ command: string }>("connectors/telegram/pair", json("POST", {}))).command; }
      catch (failure) { notify("error", message(failure, "Could not start Telegram pairing.")); return null; }
    },
    confirmTelegram: async () => {
      try {
        const result = await api<{ status: string }>("connectors/telegram/confirm", json("POST", {}));
        if (result.status !== "verified") { notify("info", "Still waiting for the command in a private chat with your bot."); return false; }
        notify("success", "Telegram connected."); await load(); return true;
      } catch (failure) { notify("error", message(failure, "Telegram pairing could not be confirmed.")); return false; }
    },
    connectorAction: (channel: string, action: "test" | "enable" | "disable") => run(() => api(`connectors/${channel}/${action}`, json("POST", {})), action === "test" ? `Test message queued for ${channel}.` : action === "enable" ? `${channel} alerts resumed.` : `${channel} alerts paused.`),
    savePolicy: (value: NotificationPolicy) => run(() => api("notifications/policy", json("PUT", value)), "Alert policy saved."),
    saveRetention: (value: RetentionPolicy) => run(() => api("maintenance/retention", json("PUT", value)), "Retention saved."),
    runRetention: async () => {
      try { const result = await api<{ files_removed: number }>("maintenance/retention/run", json("POST", {})); notify("success", `Cleanup finished. ${result.files_removed} stored files removed.`); await load(); }
      catch (failure) { notify("error", message(failure, "Retention cleanup failed.")); }
    },
    loadAttempts: (id: string) => api<DeliveryAttempt[]>(`notifications/deliveries/${id}/attempts`),
    retryDelivery: (delivery: Delivery) => run(() => api(`notifications/deliveries/${delivery.id}/retry`, json("POST", {})), "Delivery queued again."),
    createToken: async (input: { name: string; scopes: ApiToken["scopes"]; project_id: string | null; expires_in_days: number }) => {
      try { return await api<CreatedApiToken>("tokens", json("POST", input)); }
      catch (failure) { notify("error", message(failure, "Could not create the token.")); return null; }
    },
    revokeToken: (token: ApiToken) => run(() => api(`tokens/${token.id}`, { method: "DELETE" }), `${token.name} revoked.`),
  };

  return {
    session, loading, ready, error, upgradeHint, syncedAt, now, origin,
    projects, findings, scans, inventories, connectors, deliveries, policy, retention, health, tokens,
    notice, setNotice, notify, modal, setModal, findingId, setFindingId, projectId, setProjectId,
    query, setQuery, filters, setFilters, reload: load, actions,
  };
}

export type Workspace = ReturnType<typeof useWorkspaceState>;
const WorkspaceContext = createContext<Workspace | null>(null);

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  return <WorkspaceContext.Provider value={useWorkspaceState()}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace() {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("useWorkspace must be used inside WorkspaceProvider");
  return value;
}
