import type { Finding } from "../../lib/api.ts";
import { SEVERITIES, severityOf, type Severity } from "./format.ts";

// Everything the overview charts need, computed in the browser from findings' own timestamps
// (first_seen_at and resolved_at), so no backend history endpoint is required.

export const DAY = 86_400_000;
export type Counts = Record<Severity, number>;
export type SeriesPoint = { at: number; counts: Counts; total: number };

export const emptyCounts = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });

/** Open findings per severity, sampled once per rolling day ending at `now`. */
export function openSeries(findings: Finding[], now: number, days: number): SeriesPoint[] {
  const spans = findings.map((finding) => ({
    start: Date.parse(finding.first_seen_at),
    end: finding.resolved_at ? Date.parse(finding.resolved_at) : Infinity,
    severity: severityOf(finding.severity),
  }));
  const points: SeriesPoint[] = [];
  for (let back = days - 1; back >= 0; back -= 1) {
    const at = now - back * DAY;
    const counts = emptyCounts();
    let total = 0;
    for (const span of spans) {
      if (span.start <= at && span.end > at) { counts[span.severity] += 1; total += 1; }
    }
    points.push({ at, counts, total });
  }
  return points;
}

/** How a value changed against the point `daysBack` before the last one; null without enough history. */
export function change(series: SeriesPoint[], daysBack: number, pick: (point: SeriesPoint) => number) {
  if (series.length <= daysBack) return null;
  return pick(series[series.length - 1]) - pick(series[series.length - 1 - daysBack]);
}

export const urgent = (point: SeriesPoint) => point.counts.critical + point.counts.high;

/** Median days from first detection to resolution, for findings resolved within the window. */
export function medianResolveDays(findings: Finding[], now: number, windowDays = 90) {
  const durations = findings
    .filter((finding) => finding.resolved_at && now - Date.parse(finding.resolved_at) <= windowDays * DAY && Date.parse(finding.resolved_at) >= Date.parse(finding.first_seen_at))
    .map((finding) => (Date.parse(finding.resolved_at as string) - Date.parse(finding.first_seen_at)) / DAY)
    .sort((a, b) => a - b);
  if (!durations.length) return { days: null, count: 0 };
  const middle = Math.floor(durations.length / 2);
  const days = durations.length % 2 ? durations[middle] : (durations[middle - 1] + durations[middle]) / 2;
  return { days, count: durations.length };
}

export type AgeBucket = { label: string; counts: Counts; total: number };
const BUCKETS: Array<{ label: string; below: number }> = [
  { label: "Under 7 days", below: 7 },
  { label: "7 to 30 days", below: 30 },
  { label: "30 to 90 days", below: 90 },
  { label: "Over 90 days", below: Infinity },
];

/** Open findings grouped by how long they have been open. */
export function ageBuckets(open: Finding[], now: number): AgeBucket[] {
  const buckets = BUCKETS.map((bucket) => ({ label: bucket.label, counts: emptyCounts(), total: 0 }));
  for (const finding of open) {
    const age = (now - Date.parse(finding.first_seen_at)) / DAY;
    const index = BUCKETS.findIndex((bucket) => age < bucket.below);
    buckets[index].counts[severityOf(finding.severity)] += 1;
    buckets[index].total += 1;
  }
  return buckets;
}

// Common remediation targets, in days. Findings without a target (low, unknown) are never "overdue".
export const TARGET_DAYS: Partial<Record<Severity, number>> = { critical: 7, high: 30, medium: 90 };

/** Open findings older than their severity's target, excluding ones with an accepted risk. */
export function pastTarget(open: Finding[], now: number) {
  return open.filter((finding) => {
    const target = TARGET_DAYS[severityOf(finding.severity)];
    return target !== undefined && finding.workflow_status !== "risk_accepted" && (now - Date.parse(finding.first_seen_at)) / DAY > target;
  }).length;
}

/** A rounded-up axis maximum with a tidy step, e.g. 62 -> { max: 70, step: 10 }. */
export function axis(value: number, target = 4) {
  const raw = Math.max(value, 1) / target;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  // Counts of findings are whole numbers, so a step is never smaller than one.
  const step = Math.max(1, ([1, 2, 5, 10].find((candidate) => candidate * magnitude >= raw) ?? 10) * magnitude);
  return { max: Math.ceil(Math.max(value, 1) / step) * step, step };
}

export const stackOrder: Severity[] = [...SEVERITIES];
