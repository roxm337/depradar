import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { ComponentCoverage, ComponentMatch, ComponentSnapshot } from "../../lib/api.ts";
import { coverageNote, noMatchText, searchPath, summarize, versionLabel } from "./packages-logic.ts";

const snapshot = (project: string, inventory: string): ComponentSnapshot => ({ project_id: project, project_name: project, inventory_id: inventory, filename: "package-lock.json", target_path: "package-lock.json", revision: null, uploaded_at: "2026-11-01T00:00:00Z" });
const match = (project: string, inventory: string, version: string): ComponentMatch => ({ ecosystem: "npm", name: "lodash", version, purl: null, snapshot: snapshot(project, inventory), indexed_by: { scan_id: "s", status: "succeeded", complete: true, completed_at: null, coverage_notes: [] }, open_findings: 0 });
const coverage = (overrides: Partial<ComponentCoverage> = {}): ComponentCoverage => ({ snapshots: 3, indexed: 3, ecosystems: ["npm"], not_indexed: [], partial: [], ...overrides });

describe("searchPath", () => {
  test("needs a name and passes only the filters that are set", () => {
    assert.equal(searchPath({ name: "  ", ecosystem: "", version: "" }), null);
    assert.equal(searchPath({ name: " lodash ", ecosystem: "", version: "" }), "components?name=lodash");
    assert.equal(searchPath({ name: "@scope/pkg", ecosystem: "npm", version: " 1.0.0 " }), "components?name=%40scope%2Fpkg&ecosystem=npm&version=1.0.0");
  });
});

describe("summarize", () => {
  test("counts projects and manifests once and orders versions by spread", () => {
    const summary = summarize([match("a", "a1", "4.17.20"), match("a", "a2", "4.17.21"), match("b", "b1", "4.17.21"), match("c", "c1", "")]);
    assert.equal(summary.projects, 3);
    assert.equal(summary.manifests, 4);
    assert.deepEqual(summary.versions.map((row) => [row.version, row.manifests]), [["4.17.21", 2], ["", 1], ["4.17.20", 1]]);
  });
  test("orders equal counts by numeric version", () => {
    const summary = summarize([match("a", "a1", "1.10.0"), match("b", "b1", "1.9.0")]);
    assert.deepEqual(summary.versions.map((row) => row.version), ["1.9.0", "1.10.0"]);
  });
});

describe("coverage messages", () => {
  test("say nothing when every manifest is indexed by a complete scan", () => {
    assert.equal(coverageNote(coverage()), null);
    assert.equal(noMatchText("lodash", coverage()), "No current monitored manifest lists lodash. Searched 3 indexed manifests.");
  });
  test("name unindexed and partial manifests so a miss never reads as not used", () => {
    const partial = { ...snapshot("p", "p1"), indexed_by: match("p", "p1", "1").indexed_by };
    const value = coverage({ indexed: 2, not_indexed: [snapshot("x", "x1")], partial: [partial] });
    assert.equal(coverageNote(value), "1 manifest is not indexed yet and not searched; 1 manifest was indexed by an incomplete scan and may be missing packages.");
    assert.equal(noMatchText("lodash", value), "No current monitored manifest lists lodash. Searched 2 indexed manifests; 1 manifest is not indexed yet and not searched; 1 manifest was indexed by an incomplete scan and may be missing packages.");
  });
  test("label unpinned versions", () => {
    assert.equal(versionLabel(""), "Unpinned");
    assert.equal(versionLabel("1.0.0"), "1.0.0");
  });
});
