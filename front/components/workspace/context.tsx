"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, json, setCsrfToken, UNAUTHORIZED_EVENT, type ApiToken, type Connector, type CreatedApiToken, type DecisionDetail, type DecisionSummary, type Delivery, type DeliveryAttempt, type Finding, type FindingDecision, type Identities, type IdentityInput, type Inventory, type NotificationPolicy, type OperationsHealth, type Policies, type PolicyRules, type PolicyVersion, type Project, type ReportFormat, type RetentionPolicy, type Scan, type TrustedIdentity } from "@/lib/api";
import { cadence, channelLabel, supportedInventory } from "@/components/workspace/format";
import { defaultFilters, type FindingFilters } from "@/components/workspace/findings-logic";
import { DEFAULT_RULES, normalizeRules, reportFile } from "@/components/workspace/policy-logic";

export type Session = "checking" | "ready" | "offline";
export type Notice = { kind: "success" | "error" | "info"; text: string } | null;
export type ModalState = { kind: "project" } | { kind: "upload"; projectId?: string } | { kind: "risk"; findingId: string } | { kind: "retire"; projectId: string; targetPath: string } | { kind: "connector"; channel: "email" | "telegram" } | { kind: "token" } | null;
export type Filters = FindingFilters;
export type EmailInput = { host: string; port: number; username: string; sender: string; recipient: string; tls_mode: string };
export type UploadInput = { projectId: string; file: File; targetPath: string; revision: string };

const defaultPolicy: NotificationPolicy = { immediate_min_severity: "high", timezone: "UTC", digest_hour: 8, include_details: false, quiet_hours_start: null, quiet_hours_end: null };
const defaultPolicies: Policies = { installation: { id: null, scope: "installation", project_id: null, version: 0, rules: DEFAULT_RULES, note: "", created_at: null }, projects: [] };
const DECISION_PAGE = 100;

/** Which milestone endpoints the API answered; an older build renders the pages with an upgrade note. */
export type Features = { decisions: boolean; policies: boolean; identities: boolean };

// An endpoint this API build does not have answers 404 or 405; anything else is a real failure.
const missing = (failure: unknown) => failure instanceof ApiError && (failure.status === 404 || failure.status === 405);

function normalizePolicies(value: Policies): Policies {
  const version = (row: PolicyVersion): PolicyVersion => ({ ...row, rules: row.rules ? normalizeRules(row.rules) : row.scope === "installation" ? DEFAULT_RULES : null, note: row.note ?? "" });
  return { installation: version(value.installation), projects: (value.projects ?? []).map((row) => ({ ...row, policy: version(row.policy), effective: normalizeRules(row.effective) })) };
}

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

const BACKGROUND_REFRESH_MS = 60_000;

const message = (failure: unknown, fallback: string) => failure instanceof Error ? failure.message : fallback;

function useWorkspaceState() {
  const router = useRouter();
  const [session, setSession] = useState<Session>("checking");
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [dataFailed, setDataFailed] = useState(false);
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
  const [decisions, setDecisions] = useState<DecisionSummary[]>([]);
  const [policies, setPolicies] = useState<Policies>(defaultPolicies);
  const [identities, setIdentities] = useState<Identities>({ audience: "", identities: [] });
  const [features, setFeatures] = useState<Features>({ decisions: true, policies: true, identities: true });
  const [notice, setNotice] = useState<Notice>(null);
  const [modal, setModal] = useState<ModalState>(null);
  const [findingId, setFindingId] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const liveDataLoaded = useRef(false);
  const pollInFlight = useRef(false);
  const loadInFlight = useRef(false);
  const lastLoadedAt = useRef(0);

  const load = useCallback(async (silent = true) => {
    if (!silent) setLoading(true);
    loadInFlight.current = true;
    let signedIn = false;
    try {
      const status = await api<{ initialized: boolean }>("auth/status");
      if (!status.initialized) { router.replace("/login"); return; }
      // A 401 raises UNAUTHORIZED_EVENT, whose listener sends the browser to the login page.
      const me = await api<{ csrf_token: string }>("auth/me");
      setCsrfToken(me.csrf_token);
      signedIn = true;
      setSession("ready");
      const projectRows = await loadAllPages<Project>((offset) => api<Project[]>(`projects?limit=100&offset=${offset}`));
      const available: Features = { decisions: true, policies: true, identities: true };
      // Milestone endpoints degrade on their own: an older API still renders the rest of the workspace.
      const optional = <T,>(key: keyof Features, request: Promise<T>, fallback: T) => request.catch((failure) => { if (missing(failure)) available[key] = false; return fallback; });
      const [findingRows, scanRows, inventoryRows, connectorRows, deliveryRows, policyValue, retentionValue, healthValue, tokenRows, decisionRows, policyRows, identityRows] = await Promise.all([
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
        optional("decisions", api<DecisionSummary[]>(`ci/decisions?limit=${DECISION_PAGE}`), [] as DecisionSummary[]),
        optional("policies", api<Policies>("policies").then(normalizePolicies), defaultPolicies),
        optional("identities", api<Identities>("identities"), { audience: "", identities: [] } as Identities),
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
      setDecisions(decisionRows);
      setPolicies(policyRows);
      setIdentities(identityRows);
      setFeatures(available);
      setError("");
      setDataFailed(false);
      setSyncedAt(new Date().toISOString());
      liveDataLoaded.current = true;
      lastLoadedAt.current = Date.now();
      setReady(true);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) return;
      setError(message(failure, "Could not load workspace data."));
      // The session turns ready before the data arrives. If the first data load fails there is
      // nothing to keep showing, so show the retryable unavailable screen instead of skeletons.
      setDataFailed(signedIn && !liveDataLoaded.current);
      setSession(liveDataLoaded.current ? "ready" : "offline");
    } finally { loadInFlight.current = false; if (!silent) setLoading(false); }
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
    // CI pipelines and the scheduler change data without this tab knowing, so an idle
    // dashboard reloads in the background while visible, never overlapping another load.
    if (session !== "ready") return;
    const refresh = () => {
      if (document.visibilityState !== "visible" || loadInFlight.current) return;
      if (Date.now() - lastLoadedAt.current < BACKGROUND_REFRESH_MS - 1000) return;
      void load();
    };
    const timer = window.setInterval(refresh, BACKGROUND_REFRESH_MS);
    document.addEventListener("visibilitychange", refresh);
    return () => { window.clearInterval(timer); document.removeEventListener("visibilitychange", refresh); };
  }, [load, session]);
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
      if (file.size > 10 * 1024 * 1024) { notify("error", "Manifests must be 10 MB or smaller."); return false; }
      const params = new URLSearchParams({ filename: file.name });
      if (targetPath.trim()) params.set("target_path", targetPath.trim());
      if (revision.trim()) params.set("revision", revision.trim());
      return run(async () => api(`projects/${target}/inventories?${params}`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body: await file.arrayBuffer() }), "Manifest uploaded. Its scan is queued.");
    },
    rescan: (inventoryId: string, label: string) => run(() => api(`inventories/${inventoryId}/scans`, json("POST", {})), `A fresh scan was queued for ${label}.`),
    retireTarget: async (project: Project, targetPath: string) => {
      try {
        const result = await api<{ resolved_findings: number }>(`projects/${project.id}/targets/retire`, json("POST", { target_path: targetPath }));
        const resolved = result.resolved_findings;
        notify("success", `${targetPath} retired. ${resolved} open finding${resolved === 1 ? " was" : "s were"} resolved without alerts, and the history is kept.`);
        await load();
        return true;
      } catch (failure) { notify("error", message(failure, "Could not retire the manifest.")); return false; }
    },
    rescanAll: (inventoryIds: string[], label: string) => run(() => Promise.all(inventoryIds.map((id) => api(`inventories/${id}/scans`, json("POST", {})))), `${inventoryIds.length} scans queued for ${label}.`),
    setMonitoring: (project: Project, enabled: boolean, hours: number) => run(() => api(`projects/${project.id}/monitoring`, json("PUT", { enabled, interval_hours: hours })), enabled ? `${project.name} is now scanned ${cadence(hours)}.` : `Scheduled scans paused for ${project.name}.`),
    setAlerts: (project: Project, enabled: boolean, threshold: string) => run(() => api(`projects/${project.id}/notifications`, json("PUT", { enabled, immediate_min_severity: threshold })), `Alert settings saved for ${project.name}.`),
    // Acknowledges many findings in batches, reloads once, and reports how many did not go through.
    bulkAcknowledge: async (targets: Finding[]) => {
      let done = 0;
      let reason = "";
      await mapInBatches(targets, 5, async (finding) => {
        try { await api(`findings/${finding.id}/acknowledge`, json("POST", { note: "" })); done += 1; }
        catch (failure) { reason = reason || message(failure, "Request failed."); }
      });
      const failed = targets.length - done;
      if (done) await load();
      if (!failed) notify("success", `${done} finding${done === 1 ? "" : "s"} acknowledged.`);
      else notify(done ? "info" : "error", `${done} acknowledged, ${failed} could not be: ${reason}`);
      return { done, failed };
    },
    acknowledge: (finding: Finding) => run(() => api(`findings/${finding.id}/acknowledge`, json("POST", { note: "" })), `${finding.package_name} acknowledged.`),
    acceptRisk: (finding: Finding, reason: string, expiresAt: string) => run(() => api(`findings/${finding.id}/risk-acceptance`, json("POST", { reason, expires_at: expiresAt })), "Risk acceptance recorded."),
    clearDecision: (finding: Finding) => run(() => api(finding.workflow_status === "risk_accepted" ? `findings/${finding.id}/risk-acceptance` : `findings/${finding.id}/acknowledge`, { method: "DELETE" }), "Review removed; the finding needs review again."),
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
    connectorAction: (channel: string, action: "test" | "enable" | "disable") => run(() => api(`connectors/${channel}/${action}`, json("POST", {})), action === "test" ? `${channelLabel(channel)} test message queued.` : action === "enable" ? `${channelLabel(channel)} alerts resumed.` : `${channelLabel(channel)} alerts paused.`),
    savePolicy: (value: NotificationPolicy) => run(() => api("notifications/policy", json("PUT", value)), "Alert settings saved."),
    saveRetention: (value: RetentionPolicy) => run(() => api("maintenance/retention", json("PUT", value)), "Retention saved."),
    runRetention: async () => {
      try { const result = await api<{ files_removed: number }>("maintenance/retention/run", json("POST", {})); notify("success", `Cleanup finished. ${result.files_removed} stored files removed.`); await load(); }
      catch (failure) { notify("error", message(failure, "Retention cleanup failed.")); }
    },
    loadAttempts: (id: string) => api<DeliveryAttempt[]>(`notifications/deliveries/${id}/attempts`),
    retryDelivery: (delivery: Delivery) => run(() => api(`notifications/deliveries/${delivery.id}/retry`, json("POST", {})), "Message queued to send again."),
    createToken: async (input: { name: string; scopes: ApiToken["scopes"]; project_id: string | null; expires_in_days: number }) => {
      try { return await api<CreatedApiToken>("tokens", json("POST", input)); }
      catch (failure) { notify("error", message(failure, "Could not create the token.")); return null; }
    },
    revokeToken: (token: ApiToken) => run(() => api(`tokens/${token.id}`, { method: "DELETE" }), `${token.name} revoked.`),
    saveInstallationPolicy: async (rules: PolicyRules, note: string) => {
      try {
        const saved = await api<PolicyVersion>("policies/installation", json("PUT", { rules, note }));
        notify("success", `Global policy saved as version ${saved.version}. It applies from the next pipeline run.`);
        await load();
        return true;
      } catch (failure) { notify("error", message(failure, "Could not save the global policy.")); return false; }
    },
    saveProjectPolicy: async (project: Project, rules: PolicyRules | null, note: string) => {
      try {
        const saved = await api<PolicyVersion>(`policies/projects/${project.id}`, json("PUT", { rules, note }));
        notify("success", rules ? `Policy for ${project.name} saved as version ${saved.version}.` : `${project.name} now follows the global policy.`);
        await load();
        return true;
      } catch (failure) { notify("error", message(failure, "Could not save the project policy.")); return false; }
    },
    loadPolicyVersions: (projectId: string | null) => api<PolicyVersion[]>(`policies/versions${projectId ? `?project_id=${encodeURIComponent(projectId)}` : ""}`).then((rows) => rows.map((row) => ({ ...row, rules: row.rules ? normalizeRules(row.rules) : null }))),
    loadDecision: (id: string) => api<DecisionDetail>(`ci/decisions/${encodeURIComponent(id)}`),
    // Reports render from the stored decision, so the download always matches what the pipeline saw.
    downloadDecisionReport: async (id: string, format: ReportFormat) => {
      try {
        const response = await fetch(`/api/backend/ci/decisions/${encodeURIComponent(id)}?format=${format}`, { credentials: "same-origin", cache: "no-store" });
        if (response.status === 401) { window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)); return false; }
        if (!response.ok) {
          const payload = (await response.json().catch(() => ({}))) as { detail?: string };
          throw new ApiError(payload.detail || `Request failed (${response.status})`, response.status);
        }
        const file = reportFile(id, format);
        const url = URL.createObjectURL(new Blob([await response.text()], { type: file.type }));
        const link = document.createElement("a");
        link.href = url;
        link.download = file.name;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        return true;
      } catch (failure) { notify("error", message(failure, "Could not download the report.")); return false; }
    },
    createIdentity: async (input: IdentityInput) => {
      try {
        const created = await api<TrustedIdentity>("identities", json("POST", input));
        notify("success", `${created.repository} can now sign in to DepRadar from its pipeline.`);
        await load();
        return created;
      } catch (failure) { notify("error", message(failure, "Could not add the trusted identity.")); return null; }
    },
    removeIdentity: (identity: TrustedIdentity) => run(() => api(`identities/${identity.id}`, { method: "DELETE" }), `${identity.repository} can no longer sign in from its pipeline.`),
  };

  return {
    session, loading, ready, error, dataFailed, upgradeHint, syncedAt, now, origin,
    projects, findings, scans, inventories, connectors, deliveries, policy, retention, health, tokens,
    decisions, policies, identities, features,
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
