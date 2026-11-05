import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { coverageBadge, plainDescription, scanDuration, sortProjectRows, type ProjectRow } from "./projects-format.ts";

const row = (name: string, open: number, urgent: number, scannedAt: number | null): ProjectRow => ({ name, open, urgent, scannedAt });
const names = (rows: ProjectRow[]) => rows.map((item) => item.name);

describe("plainDescription", () => {
  test("hides the demo suffix and nothing else", () => {
    assert.equal(plainDescription("Customer API. (Demo data.)"), "Customer API.");
    assert.equal(plainDescription("Customer API."), "Customer API.");
    assert.equal(plainDescription("(Demo data.) is not a suffix here"), "(Demo data.) is not a suffix here");
    assert.equal(plainDescription(""), "");
  });
});

describe("scanDuration", () => {
  test("formats seconds, minutes and hours", () => {
    const start = "2026-11-04T10:00:00Z";
    assert.equal(scanDuration(start, null), "—");
    assert.equal(scanDuration(start, "2026-11-04T10:00:00Z"), "<1s");
    assert.equal(scanDuration(start, "2026-11-04T10:00:42Z"), "42s");
    assert.equal(scanDuration(start, "2026-11-04T10:01:04Z"), "1m 04s");
    assert.equal(scanDuration(start, "2026-11-04T12:05:30Z"), "2h 05m");
  });
});

describe("coverageBadge", () => {
  test("maps each coverage state to a label and tone", () => {
    assert.deepEqual(coverageBadge("verified"), { label: "Verified", tone: "tag-ok" });
    assert.deepEqual(coverageBadge("incomplete"), { label: "Partial", tone: "tag-warn" });
    assert.equal(coverageBadge("unscanned").label, "Not scanned");
    assert.equal(coverageBadge("pending").label, "In progress");
    assert.equal(coverageBadge("none").label, "No manifests");
    assert.equal(coverageBadge("unknown").label, "Unknown");
  });
});

describe("sortProjectRows", () => {
  const rows = [row("b", 5, 1, 200), row("a", 5, 3, 100), row("c", 9, 0, null), row("d", 1, 1, 300)];

  test("sorts by critical and high, breaking ties by open count then name", () => {
    assert.deepEqual(names(sortProjectRows(rows, "urgent", "desc")), ["a", "b", "d", "c"]);
    assert.deepEqual(names(sortProjectRows(rows, "urgent", "asc")), ["c", "b", "d", "a"]);
  });

  test("sorts by open findings and by name in both directions", () => {
    assert.deepEqual(names(sortProjectRows(rows, "open", "desc")), ["c", "a", "b", "d"]);
    assert.deepEqual(names(sortProjectRows(rows, "name", "desc")), ["d", "c", "b", "a"]);
  });

  test("never scanned projects stay last whichever way the scan column sorts", () => {
    assert.deepEqual(names(sortProjectRows(rows, "scan", "desc")), ["d", "b", "a", "c"]);
    assert.deepEqual(names(sortProjectRows(rows, "scan", "asc")), ["a", "b", "d", "c"]);
  });

  test("does not mutate its input", () => {
    const copy = [...rows];
    sortProjectRows(rows, "name", "asc");
    assert.deepEqual(rows, copy);
  });
});
