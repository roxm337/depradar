// Pure helpers for the projects table and project drawer. No React and no `@/` imports, so
// `node --test` can run them.

/** The demo seed marks its projects; the suffix is noise in the interface. */
export function plainDescription(text: string): string {
  return text.replace(/\s*\(Demo data\.\)\s*$/i, "").trim();
}

/** "42s", "1m 04s", "2h 05m": how long a scan took, or a dash while it is unfinished. */
export function scanDuration(createdAt: string, completedAt: string | null): string {
  if (!completedAt) return "—";
  const seconds = Math.max(0, Math.round((Date.parse(completedAt) - Date.parse(createdAt)) / 1000));
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`;
  return `${Math.floor(seconds / 3600)}h ${String(Math.floor((seconds % 3600) / 60)).padStart(2, "0")}m`;
}

type Coverage = "none" | "unknown" | "unscanned" | "pending" | "incomplete" | "verified";

/** The coverage badge: a short label and the `.tag` variant that carries its tone. */
export function coverageBadge(state: Coverage): { label: string; tone: string } {
  switch (state) {
    case "verified": return { label: "Verified", tone: "tag-ok" };
    case "incomplete": return { label: "Incomplete", tone: "tag-warn" };
    case "unscanned": return { label: "Not scanned", tone: "" };
    case "pending": return { label: "In progress", tone: "tag-check" };
    case "none": return { label: "No manifests", tone: "" };
    default: return { label: "Unknown", tone: "" };
  }
}

export type ProjectSortKey = "name" | "open" | "urgent" | "scan";
export type SortDirection = "asc" | "desc";
export type ProjectRow = { name: string; open: number; urgent: number; scannedAt: number | null };

/**
 * Sorts project rows by a column. Ties fall back to a stable order, and projects that were never
 * scanned always sort last, whichever direction is chosen, so the table never leads with blanks.
 */
export function sortProjectRows<T extends ProjectRow>(rows: T[], key: ProjectSortKey, direction: SortDirection): T[] {
  const sign = direction === "asc" ? 1 : -1;
  const byName = (a: T, b: T) => a.name.localeCompare(b.name);
  return [...rows].sort((a, b) => {
    switch (key) {
      case "name": return sign * byName(a, b);
      case "open": return sign * (a.open - b.open) || b.urgent - a.urgent || byName(a, b);
      case "urgent": return sign * (a.urgent - b.urgent) || b.open - a.open || byName(a, b);
      case "scan": {
        if (a.scannedAt === null || b.scannedAt === null) return Number(a.scannedAt === null) - Number(b.scannedAt === null) || byName(a, b);
        return sign * (a.scannedAt - b.scannedAt) || byName(a, b);
      }
    }
  });
}
