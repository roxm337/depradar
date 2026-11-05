import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ageLabel, buildTimeline, decisionTitle, percentileLabel } from "./drawer-format.ts";

describe("percentileLabel", () => {
  test("never prints 100%", () => {
    assert.equal(percentileLabel(1), "Higher than 99.9% of scored CVEs");
    assert.equal(percentileLabel(0.9995), "Higher than 99.9% of scored CVEs");
    assert.equal(percentileLabel(1.4), "Higher than 99.9% of scored CVEs");
  });
  test("keeps precision only near the top", () => {
    assert.equal(percentileLabel(0.994), "Higher than 99.4% of scored CVEs");
    assert.equal(percentileLabel(0.876), "Higher than 88% of scored CVEs");
    assert.equal(percentileLabel(0), "Higher than 0% of scored CVEs");
  });
  test("handles a missing percentile", () => {
    assert.equal(percentileLabel(null), "Percentile unavailable");
  });
});

describe("ageLabel", () => {
  const now = Date.parse("2026-11-04T12:00:00Z");
  test("counts whole days", () => {
    assert.equal(ageLabel(now, "2026-11-04T01:00:00Z"), "under a day");
    assert.equal(ageLabel(now, "2026-11-03T08:00:00Z"), "1 day");
    assert.equal(ageLabel(now, "2026-09-07T12:00:00Z"), 58 + " days");
  });
  test("stops the clock at the resolution date", () => {
    assert.equal(ageLabel(now, "2026-10-01T12:00:00Z", "2026-10-11T12:00:00Z"), "10 days");
  });
});

describe("decisionTitle", () => {
  test("names the known actions and falls back readably", () => {
    assert.equal(decisionTitle("acknowledged"), "Acknowledged");
    assert.equal(decisionTitle("risk_expired"), "Risk acceptance expired");
    assert.equal(decisionTitle("something_new"), "Something new");
  });
});

describe("buildTimeline", () => {
  test("orders detection, decisions and resolution newest first", () => {
    const finding = { id: "f", first_seen_at: "2026-10-01T00:00:00Z", resolved_at: "2026-10-20T00:00:00Z", status: "resolved" };
    const events = buildTimeline(finding, [
      { action: "acknowledged", note: "Triaged", expires_at: null, created_at: "2026-10-05T00:00:00Z" },
      { action: "risk_accepted", note: "Not reachable", expires_at: "2026-12-01T00:00:00Z", created_at: "2026-10-10T00:00:00Z" },
    ]);
    assert.deepEqual(events.map((event) => event.title), ["Resolved", "Risk accepted", "Acknowledged", "Detected"]);
    assert.equal(events[1].expiresAt, "2026-12-01T00:00:00Z");
  });
  test("an open finding has no resolution entry", () => {
    const finding = { id: "f", first_seen_at: "2026-10-01T00:00:00Z", resolved_at: null, status: "open" };
    assert.deepEqual(buildTimeline(finding, []).map((event) => event.title), ["Detected"]);
  });
});
