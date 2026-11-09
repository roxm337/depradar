import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Finding } from "../../lib/api.ts";
import {
  acknowledgeable, ageLabel, BUILTIN_VIEWS, csvCell, csvFileName, decisionOf, defaultFilters, filterFindings, isFiltered, pageWindow,
  parseColumns, parsePageSize, parseViews, rangeIds, sameView, serializeViews, severityCounts, sortFindings, toCsv, toggleSort, upsertView,
  type FindingFilters,
} from "./findings-logic.ts";

const DAY = 86_400_000;
const NOW = Date.parse("2026-11-04T12:00:00Z");
const ago = (days: number) => new Date(NOW - days * DAY).toISOString();

function finding(id: string, extra: Partial<Finding> = {}): Finding {
  return {
    id, project_id: "p1", target_filename: "package-lock.json", target_path: "apps/web/package-lock.json", revision: null, ecosystem: "npm",
    package_name: "lodash", package_version: "4.17.15", purl: null, advisory_ids: ["GHSA-aaaa-bbbb-cccc", "CVE-2021-23337"], summary: "Command injection",
    severity: "high", cvss_vectors: [], epss_score: 0.1, epss_percentile: 0.5, kev_known: false, intel_updated_at: null, fixed_versions: ["4.17.21"],
    status: "open", evidence: [], first_seen_at: ago(10), last_seen_at: ago(0), resolved_at: null, workflow_status: "open", decision_note: "",
    risk_until: null, acknowledged_at: null, ...extra,
  };
}

const names = new Map([["p1", "acme/api"], ["p2", "acme/storefront"]]);
const filters = (patch: Partial<FindingFilters> = {}): FindingFilters => ({ ...defaultFilters, ...patch });

const sample = [
  finding("crit-old", { severity: "critical", package_name: "pillow", package_version: "9.5.0", first_seen_at: ago(58), kev_known: true, epss_score: 0.71, fixed_versions: ["10.0.1"], advisory_ids: ["GHSA-j7hp-h8jx-5ppr"] }),
  finding("high-new", { severity: "high", package_name: "axios", package_version: "0.21.1", first_seen_at: ago(2), epss_score: 0.01, project_id: "p2", fixed_versions: ["0.21.2"] }),
  finding("high-nofix", { severity: "high", package_name: "ip", package_version: "1.1.5", first_seen_at: ago(20), epss_score: null, fixed_versions: [], workflow_status: "acknowledged" }),
  finding("low-accepted", { severity: "low", package_name: "devise", package_version: "4.7.3", first_seen_at: ago(30), workflow_status: "risk_accepted", risk_until: "2026-12-01T00:00:00Z", project_id: "p2" }),
  finding("med-resolved", { severity: "medium", package_name: "semver", package_version: "5.7.1", status: "resolved", resolved_at: ago(1), first_seen_at: ago(40) }),
  finding("unknown", { severity: "weird", package_name: "certifi", package_version: "2022.9.24", first_seen_at: ago(5) }),
];
const ids = (rows: Finding[]) => rows.map((row) => row.id);

describe("filterFindings", () => {
  test("defaults to open findings only", () => {
    assert.deepEqual(ids(filterFindings(sample, filters(), "", names)).sort(), ["crit-old", "high-new", "high-nofix", "low-accepted", "unknown"].sort());
    assert.deepEqual(ids(filterFindings(sample, filters({ status: "resolved" }), "", names)), ["med-resolved"]);
    assert.equal(filterFindings(sample, filters({ status: "all" }), "", names).length, 6);
  });

  test("severity is multi-select and unrecognised severities count as unknown", () => {
    assert.deepEqual(ids(filterFindings(sample, filters({ severities: ["critical", "low"] }), "", names)).sort(), ["crit-old", "low-accepted"]);
    assert.deepEqual(ids(filterFindings(sample, filters({ severities: ["unknown"] }), "", names)), ["unknown"]);
  });

  test("decision filters on the workflow state", () => {
    assert.deepEqual(ids(filterFindings(sample, filters({ decision: "acknowledged" }), "", names)), ["high-nofix"]);
    assert.deepEqual(ids(filterFindings(sample, filters({ decision: "risk_accepted" }), "", names)), ["low-accepted"]);
    assert.deepEqual(ids(filterFindings(sample, filters({ decision: "decided" }), "", names)).sort(), ["high-nofix", "low-accepted"]);
    assert.equal(filterFindings(sample, filters({ decision: "open" }), "", names).length, 3);
  });

  test("project, known exploited, and fix available combine", () => {
    assert.deepEqual(ids(filterFindings(sample, filters({ project: "p2" }), "", names)).sort(), ["high-new", "low-accepted"]);
    assert.deepEqual(ids(filterFindings(sample, filters({ exploited: true }), "", names)), ["crit-old"]);
    assert.deepEqual(ids(filterFindings(sample, filters({ fixable: true, project: "p2" }), "", names)).sort(), ["high-new", "low-accepted"]);
    assert.ok(!ids(filterFindings(sample, filters({ fixable: true }), "", names)).includes("high-nofix"));
  });

  test("every search term must match, across package, advisory, project, and path", () => {
    assert.deepEqual(ids(filterFindings(sample, filters(), "pillow", names)), ["crit-old"]);
    assert.deepEqual(ids(filterFindings(sample, filters(), "ghsa-j7hp", names)), ["crit-old"]);
    assert.deepEqual(ids(filterFindings(sample, filters(), "STOREFRONT axios", names)), ["high-new"]);
    assert.deepEqual(ids(filterFindings(sample, filters(), "storefront pillow", names)), []);
    assert.equal(filterFindings(sample, filters(), "package-lock", names).length, 5);
  });
});

describe("severityCounts and isFiltered", () => {
  test("counts ignore the severity filter but respect every other one", () => {
    const counts = severityCounts(sample, filters({ severities: ["critical"], project: "p2" }), "", names);
    assert.deepEqual(counts, { critical: 0, high: 1, medium: 0, low: 1, unknown: 0 });
  });

  test("anything other than the defaults counts as filtered", () => {
    assert.equal(isFiltered(defaultFilters, ""), false);
    assert.equal(isFiltered(defaultFilters, "  "), false);
    assert.equal(isFiltered(defaultFilters, "x"), true);
    assert.equal(isFiltered(filters({ status: "all" }), ""), true);
    assert.equal(isFiltered(filters({ exploited: true }), ""), true);
    assert.equal(isFiltered(filters({ sort: { key: "age", dir: "asc" } }), ""), false);
  });
});

describe("sortFindings", () => {
  const order = (sort: FindingFilters["sort"], rows = sample.filter((row) => row.status === "open")) => ids(sortFindings(rows, sort, names));

  test("priority puts the most urgent first and is stable", () => {
    const result = order({ key: "priority", dir: "desc" });
    assert.equal(result[0], "crit-old");
    assert.equal(result.at(-1), "unknown");
    assert.deepEqual(order({ key: "priority", dir: "asc" }), [...result].reverse());
  });

  test("severity, package, and project sort in both directions", () => {
    assert.deepEqual(order({ key: "severity", dir: "desc" }).slice(0, 2), ["crit-old", "high-new"]);
    assert.equal(order({ key: "severity", dir: "asc" })[0], "unknown");
    assert.deepEqual(order({ key: "package", dir: "asc" }), ["high-new", "unknown", "low-accepted", "high-nofix", "crit-old"]);
    assert.deepEqual(order({ key: "project", dir: "asc" }).slice(0, 3).every((id) => ["crit-old", "high-nofix", "unknown"].includes(id)), true);
  });

  test("fixed in lists findings without a fix last when ascending, first when descending", () => {
    assert.equal(order({ key: "fixed", dir: "asc" }).at(-1), "high-nofix");
    assert.equal(order({ key: "fixed", dir: "desc" })[0], "high-nofix");
  });

  test("epss treats a missing score as the lowest", () => {
    assert.equal(order({ key: "epss", dir: "desc" })[0], "crit-old");
    assert.equal(order({ key: "epss", dir: "asc" })[0], "high-nofix");
  });

  test("age orders by how long ago the finding was first seen", () => {
    assert.deepEqual(order({ key: "age", dir: "desc" }), ["crit-old", "low-accepted", "high-nofix", "unknown", "high-new"]);
    assert.deepEqual(order({ key: "age", dir: "asc" }), ["high-new", "unknown", "high-nofix", "low-accepted", "crit-old"]);
  });

  test("does not modify its input", () => {
    const copy = [...sample];
    sortFindings(sample, { key: "package", dir: "asc" }, names);
    assert.deepEqual(sample, copy);
  });

  test("toggleSort starts on the useful direction, then flips", () => {
    assert.deepEqual(toggleSort({ key: "priority", dir: "desc" }, "severity"), { key: "severity", dir: "desc" });
    assert.deepEqual(toggleSort({ key: "severity", dir: "desc" }, "severity"), { key: "severity", dir: "asc" });
    assert.deepEqual(toggleSort({ key: "severity", dir: "asc" }, "severity"), { key: "severity", dir: "desc" });
    assert.deepEqual(toggleSort({ key: "severity", dir: "desc" }, "package"), { key: "package", dir: "asc" });
    assert.deepEqual(toggleSort({ key: "package", dir: "asc" }, "age"), { key: "age", dir: "desc" });
  });
});

describe("presentation helpers", () => {
  test("age is shown in hours below a day and days above", () => {
    assert.equal(ageLabel(NOW, new Date(NOW - 20 * 60_000).toISOString()), "<1h");
    assert.equal(ageLabel(NOW, new Date(NOW - 6 * 3_600_000).toISOString()), "6h");
    assert.equal(ageLabel(NOW, ago(58)), "58d");
    assert.equal(ageLabel(0, ago(1)), "—");
  });

  test("decisions describe where the finding stands", () => {
    assert.deepEqual(decisionOf(sample[0]), { kind: "awaiting", label: "Not reviewed" });
    assert.deepEqual(decisionOf(sample[2]), { kind: "acknowledged", label: "Acknowledged" });
    assert.equal(decisionOf(sample[3]).kind, "accepted");
    assert.match(decisionOf(sample[3]).label, /^Risk accepted until \d{1,2} \w+ 2026$/);
    assert.deepEqual(decisionOf(sample[4]), { kind: "resolved", label: "Resolved" });
  });

  test("only open, undecided findings can be acknowledged", () => {
    assert.deepEqual(ids(sample.filter(acknowledgeable)).sort(), ["crit-old", "high-new", "unknown"]);
  });
});

describe("saved views", () => {
  test("built-in views match themselves and nothing else", () => {
    const [allOpen, criticalHigh] = BUILTIN_VIEWS;
    assert.equal(sameView(defaultFilters, "", allOpen), true);
    assert.equal(sameView(filters({ severities: ["high", "critical"] }), "", criticalHigh), true);
    assert.equal(sameView(filters({ severities: ["high"] }), "", criticalHigh), false);
    assert.equal(sameView(defaultFilters, "lodash", allOpen), false);
    assert.equal(sameView(filters({ sort: { key: "age", dir: "asc" } }), "", allOpen), true);
  });

  test("saving under an existing name replaces it; names ignore case", () => {
    let views = upsertView([], "My triage", filters({ exploited: true }), "");
    views = upsertView(views, "Backend", filters({ project: "p1" }), "pillow");
    assert.equal(views.length, 2);
    views = upsertView(views, "my TRIAGE", filters({ fixable: true }), "");
    assert.equal(views.length, 2);
    assert.equal(views[0].filters.fixable, true);
    assert.equal(views[0].filters.exploited, false);
    assert.equal(new Set(views.map((view) => view.id)).size, 2);
  });

  test("views survive a round trip and ignore corrupt storage", () => {
    const views = upsertView([], "Critical in api", filters({ severities: ["critical"], project: "p1", sort: { key: "age", dir: "desc" } }), "pillow");
    assert.deepEqual(parseViews(serializeViews(views)), views);
    assert.deepEqual(parseViews(null), []);
    assert.deepEqual(parseViews("not json"), []);
    assert.deepEqual(parseViews('{"a":1}'), []);
    assert.deepEqual(parseViews('[{"id":"x","name":"","filters":{}},{"id":1,"name":"n","filters":{}},5,null]'), []);
  });

  test("stored filters with unknown values are repaired, not trusted", () => {
    const [view] = parseViews(JSON.stringify([{ id: "v", name: "Odd", query: 7, filters: { status: "nope", severities: ["high", "bogus", 3], decision: "x", project: "", sort: { key: "bogus", dir: "up" } } }]));
    assert.deepEqual(view.filters, { ...defaultFilters, severities: ["high"] });
    assert.equal(view.query, "");
  });
});

describe("columns, paging, and selection", () => {
  test("columns default to all and ignore garbage", () => {
    assert.equal(parseColumns(null).length, 6);
    assert.deepEqual(parseColumns('["age","project","bogus"]'), ["project", "age"]);
    assert.equal(parseColumns("not json").length, 6);
    assert.deepEqual(parseColumns("[]"), []);
  });

  test("page size accepts only the offered sizes", () => {
    assert.equal(parsePageSize("50"), 50);
    assert.equal(parsePageSize("7"), 25);
    assert.equal(parsePageSize(null), 25);
  });

  test("page windows are 1-based, clamped, and empty-safe", () => {
    assert.deepEqual(pageWindow(62, 1, 25), { page: 1, pages: 3, from: 1, to: 25 });
    assert.deepEqual(pageWindow(62, 3, 25), { page: 3, pages: 3, from: 51, to: 62 });
    assert.deepEqual(pageWindow(62, 9, 25), { page: 3, pages: 3, from: 51, to: 62 });
    assert.deepEqual(pageWindow(62, 0, 25), { page: 1, pages: 3, from: 1, to: 25 });
    assert.deepEqual(pageWindow(0, 1, 25), { page: 1, pages: 1, from: 0, to: 0 });
    assert.deepEqual(pageWindow(25, 1, 25), { page: 1, pages: 1, from: 1, to: 25 });
  });

  test("a shift-click range runs either way and falls back to the target", () => {
    const list = ["a", "b", "c", "d", "e"];
    assert.deepEqual(rangeIds(list, "b", "d"), ["b", "c", "d"]);
    assert.deepEqual(rangeIds(list, "d", "b"), ["b", "c", "d"]);
    assert.deepEqual(rangeIds(list, null, "c"), ["c"]);
    assert.deepEqual(rangeIds(list, "zzz", "c"), ["c"]);
    assert.deepEqual(rangeIds(list, "a", "zzz"), []);
  });
});

describe("CSV export", () => {
  test("plain values pass through and special characters are quoted", () => {
    assert.equal(csvCell("pillow"), "pillow");
    assert.equal(csvCell(4.2), "4.2");
    assert.equal(csvCell(null), "");
    assert.equal(csvCell(undefined), "");
    assert.equal(csvCell("a,b"), '"a,b"');
    assert.equal(csvCell('say "hi"'), '"say ""hi"""');
    assert.equal(csvCell("line\nbreak"), '"line\nbreak"');
    assert.equal(csvCell("cr\rlf"), '"cr\rlf"');
  });

  test("text that a spreadsheet would run as a formula is neutralised", () => {
    for (const value of ["=SUM(A1:A9)", "+1+1", "-2+3", "@cmd", "\t=1"]) assert.ok(csvCell(value).startsWith("'") || csvCell(value).startsWith("\"'"), value);
    assert.equal(csvCell("=HYPERLINK(\"http://x\",\"y\")"), '"\'=HYPERLINK(""http://x"",""y"")"');
    assert.equal(csvCell("a=b"), "a=b");
    assert.equal(csvCell("1-2"), "1-2");
  });

  test("the export has a header, one row per finding, and CRLF line endings", () => {
    const csv = toCsv([sample[0], sample[3]], names);
    const lines = csv.split("\r\n");
    assert.equal(lines.length, 4);
    assert.equal(lines[3], "");
    assert.equal(lines[0], "Severity,Package,Version,Ecosystem,Project,Manifest,Advisories,Fixed versions,EPSS (%),Known exploited,First seen,Status,Review");
    assert.ok(lines[1].startsWith("critical,pillow,9.5.0,npm,acme/api,apps/web/package-lock.json,GHSA-j7hp-h8jx-5ppr,10.0.1,71.0,yes,"));
    assert.ok(lines[1].endsWith(",open,Not reviewed"));
    assert.match(lines[2], /^low,devise,4\.7\.3,/);
    assert.match(lines[2], /,open,Risk accepted until \d{1,2} \w+ 2026$/);
  });

  test("a hostile package name cannot become a formula in the export", () => {
    const csv = toCsv([finding("x", { package_name: "=cmd|' /C calc'!A0", summary: "+bad" })], names);
    assert.ok(csv.includes(",\"'=cmd|' /C calc'!A0\",") || csv.includes(",'=cmd|' /C calc'!A0,"));
    assert.ok(!/(^|,)=cmd/.test(csv));
  });

  test("missing EPSS exports as an empty cell; multiple IDs join with semicolons", () => {
    const csv = toCsv([finding("x", { epss_score: null, advisory_ids: ["A-1", "B-2"], fixed_versions: ["1.0", "2.0"] })], names);
    assert.ok(csv.includes(",A-1; B-2,1.0; 2.0,,no,"));
  });

  test("file name carries the date", () => {
    assert.equal(csvFileName(new Date("2026-11-04T23:59:00Z")), "depradar-findings-2026-11-04.csv");
  });
});
