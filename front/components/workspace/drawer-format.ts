// Pure helpers for the finding drawer. No React and no `@/` imports, so `node --test` can run them.

export type Decision = { action: string; note: string; expires_at: string | null; created_at: string };
export type TimelineEvent = { id: string; at: string; title: string; note: string; expiresAt: string | null; tone: "ok" | "warn" | "neutral" };

/** EPSS percentile as text. It is clamped so a near-certain score never reads "100%". */
export function percentileLabel(percentile: number | null): string {
  if (percentile === null) return "Percentile unavailable";
  const value = Math.min(99.9, Math.max(0, percentile * 100));
  return `Higher than ${value >= 99 ? value.toFixed(1) : value.toFixed(0)}% of scored CVEs`;
}

/** "today", "1 day", "58 days": how long a finding has been open. */
export function ageLabel(now: number, since: string, until?: string | null): string {
  const end = until ? Date.parse(until) : now;
  if (!end) return "—";
  const days = Math.floor((end - Date.parse(since)) / 86_400_000);
  if (days < 1) return "under a day";
  return days === 1 ? "1 day" : `${days} days`;
}

const decisionTitles: Record<string, [string, TimelineEvent["tone"]]> = {
  acknowledged: ["Acknowledged", "ok"],
  risk_accepted: ["Risk accepted", "ok"],
  ack_revoked: ["Acknowledgement revoked", "neutral"],
  risk_revoked: ["Risk acceptance revoked", "neutral"],
  risk_expired: ["Risk acceptance expired", "warn"],
};

export function decisionTitle(action: string): string {
  return decisionTitles[action]?.[0] ?? action.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

/** The finding's history, newest first: when it was detected, every decision, and its resolution. */
export function buildTimeline(finding: { id: string; first_seen_at: string; resolved_at: string | null; status: string }, decisions: Decision[]): TimelineEvent[] {
  const events: TimelineEvent[] = [{ id: `${finding.id}-detected`, at: finding.first_seen_at, title: "Detected", note: "First seen in a scan", expiresAt: null, tone: "neutral" }];
  decisions.forEach((decision, index) => {
    events.push({
      id: `${finding.id}-decision-${index}`,
      at: decision.created_at,
      title: decisionTitle(decision.action),
      note: decision.note,
      expiresAt: decision.expires_at,
      tone: decisionTitles[decision.action]?.[1] ?? "neutral",
    });
  });
  if (finding.status === "resolved" && finding.resolved_at) events.push({ id: `${finding.id}-resolved`, at: finding.resolved_at, title: "Resolved", note: "No longer present in a complete scan", expiresAt: null, tone: "ok" });
  return events.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}
