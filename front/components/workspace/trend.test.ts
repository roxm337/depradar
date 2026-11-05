import assert from "node:assert/strict";
import { test } from "node:test";
import type { Finding } from "../../lib/api.ts";
import { ageBuckets, axis, change, DAY, medianResolveDays, openSeries, pastTarget, urgent } from "./trend.ts";

const NOW = Date.parse("2026-11-04T12:00:00Z");
const ago = (days: number) => new Date(NOW - days * DAY).toISOString();

function finding(id: string, severity: string, seenDaysAgo: number, resolvedDaysAgo: number | null = null, extra: Partial<Finding> = {}): Finding {
  return {
    id, project_id: "p", target_filename: "package-lock.json", target_path: "package-lock.json", revision: null, ecosystem: "npm",
    package_name: id, package_version: "1.0.0", purl: null, advisory_ids: [id], summary: "", severity, cvss_vectors: [], epss_score: null,
    epss_percentile: null, kev_known: false, intel_updated_at: null, fixed_versions: [], status: resolvedDaysAgo === null ? "open" : "resolved",
    evidence: [], first_seen_at: ago(seenDaysAgo), last_seen_at: ago(0), resolved_at: resolvedDaysAgo === null ? null : ago(resolvedDaysAgo),
    workflow_status: "open", decision_note: "", risk_until: null, acknowledged_at: null, ...extra,
  };
}

test("the series counts a finding only between detection and resolution", () => {
  const series = openSeries([finding("a", "critical", 10, 4), finding("b", "high", 2)], NOW, 14);
  assert.equal(series.length, 14);
  const at = (daysAgo: number) => series[series.length - 1 - daysAgo];
  assert.equal(at(12).total, 0);
  assert.equal(at(8).counts.critical, 1);
  assert.equal(at(3).counts.critical, 0);
  assert.equal(at(1).counts.high, 1);
  assert.equal(at(0).total, 1);
});

test("change compares against an earlier point and needs enough history", () => {
  const series = openSeries([finding("a", "critical", 10), finding("b", "high", 2), finding("c", "low", 3, 1)], NOW, 14);
  assert.equal(change(series, 7, (point) => point.total), 1);
  assert.equal(change(series, 7, urgent), 1);
  assert.equal(change(series.slice(-3), 7, (point) => point.total), null);
});

test("median time to resolve uses only recent resolutions", () => {
  const rows = [finding("a", "high", 20, 10), finding("b", "high", 30, 10), finding("c", "low", 50, 40), finding("old", "high", 400, 300), finding("open", "high", 5)];
  const result = medianResolveDays(rows, NOW, 90);
  assert.equal(result.count, 3);
  assert.equal(result.days, 10);
  assert.deepEqual(medianResolveDays([finding("x", "low", 3)], NOW), { days: null, count: 0 });
});

test("age buckets split open findings and keep severities apart", () => {
  const buckets = ageBuckets([finding("a", "critical", 2), finding("b", "high", 7), finding("c", "high", 45), finding("d", "low", 200)], NOW);
  assert.deepEqual(buckets.map((bucket) => bucket.total), [1, 1, 1, 1]);
  assert.equal(buckets[1].counts.high, 1);
  assert.equal(buckets[3].counts.low, 1);
});

test("past target ignores low severity and accepted risk", () => {
  const rows = [
    finding("late-critical", "critical", 9), finding("fresh-critical", "critical", 3), finding("late-high", "high", 40),
    finding("late-low", "low", 400), finding("accepted", "critical", 30, null, { workflow_status: "risk_accepted" }),
  ];
  assert.equal(pastTarget(rows, NOW), 2);
});

test("axis rounds up to a tidy maximum", () => {
  assert.deepEqual(axis(62), { max: 80, step: 20 });
  assert.deepEqual(axis(0), { max: 1, step: 1 });
  assert.equal(axis(9).max % axis(9).step, 0);
});
