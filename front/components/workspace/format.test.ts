import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Inventory, Project, Scan } from "../../lib/api.ts";
import { channelLabel, deliveryEvent, latestPerTarget, projectCoverage, retiredTargets, scanEvent, sentenceCase, workspaceCoverage } from "./format.ts";

const P = "project-1";

function inventory(id: string, targetPath: string, createdAt: string, extra: Partial<Inventory> = {}): Inventory {
  return { id, project_id: P, filename: "package-lock.json", target_path: targetPath, revision: null, sha256: "0".repeat(64), size_bytes: 10, created_at: createdAt, kind: "monitor", retired_at: null, ...extra };
}

function scan(id: string, inventoryId: string, createdAt: string, extra: Partial<Scan> = {}): Scan {
  return { id, inventory_id: inventoryId, project_id: P, status: "succeeded", complete: true, engine_version: "fixture", error: null, package_count: 3, coverage_notes: [], created_at: createdAt, completed_at: createdAt, mode: "monitor", ...extra } as Scan;
}

const project = (id: string) => ({ id, name: id }) as Project;

describe("latestPerTarget", () => {
  test("keeps the newest snapshot of every manifest path", () => {
    const rows = [
      inventory("a-old", "web/package-lock.json", "2026-11-01T10:00:00Z"),
      inventory("api", "api/poetry.lock", "2026-11-01T11:00:00Z"),
      inventory("a-new", "web/package-lock.json", "2026-11-03T10:00:00Z"),
      inventory("a-mid", "web/package-lock.json", "2026-11-02T10:00:00Z"),
      inventory("other", "web/package-lock.json", "2026-11-09T10:00:00Z", { project_id: "project-2" }),
    ];
    assert.deepEqual(latestPerTarget(rows, P).map((row) => row.id), ["a-new", "api"]);
  });

  test("breaks equal timestamps by the higher ID, like the API", () => {
    const at = "2026-11-03T10:00:00Z";
    const rows = [inventory("b", "go.mod", at), inventory("c", "go.mod", at), inventory("a", "go.mod", at)];
    assert.deepEqual(latestPerTarget(rows, P).map((row) => row.id), ["c"]);
  });

  test("hides a manifest whose newest snapshot is retired", () => {
    const rows = [
      inventory("old", "web/package-lock.json", "2026-11-01T10:00:00Z", { retired_at: "2026-11-04T10:00:00Z" }),
      inventory("new", "web/package-lock.json", "2026-11-02T10:00:00Z", { retired_at: "2026-11-04T10:00:00Z" }),
      inventory("kept", "api/poetry.lock", "2026-11-02T10:00:00Z"),
    ];
    assert.deepEqual(latestPerTarget(rows, P).map((row) => row.id), ["kept"]);
    assert.deepEqual(retiredTargets(rows, P).map((row) => row.id), ["new"]);
  });

  test("a manifest uploaded again after retirement is monitored again", () => {
    const rows = [
      inventory("retired", "web/package-lock.json", "2026-11-01T10:00:00Z", { retired_at: "2026-11-02T10:00:00Z" }),
      inventory("back", "web/package-lock.json", "2026-11-03T10:00:00Z"),
    ];
    assert.deepEqual(latestPerTarget(rows, P).map((row) => row.id), ["back"]);
    assert.deepEqual(retiredTargets(rows, P), []);
  });
});

describe("projectCoverage", () => {
  const web = inventory("web", "web/package-lock.json", "2026-11-01T10:00:00Z");
  const api = inventory("api", "api/poetry.lock", "2026-11-01T10:00:00Z");

  test("no manifests and no scans", () => {
    assert.equal(projectCoverage(P, [], []).state, "none");
  });

  test("scans without any snapshot cannot prove coverage", () => {
    assert.equal(projectCoverage(P, [], [scan("s", "gone", "2026-11-01T10:00:00Z")]).state, "unknown");
  });

  test("never scanned", () => {
    assert.equal(projectCoverage(P, [web], []).state, "unscanned");
  });

  test("a failed latest scan is incomplete even after an earlier success", () => {
    const scans = [scan("ok", "web", "2026-11-01T11:00:00Z"), scan("bad", "web", "2026-11-01T12:00:00Z", { status: "failed", complete: false })];
    assert.equal(projectCoverage(P, [web], scans).state, "incomplete");
  });

  test("partial coverage and succeeded-with-gaps are incomplete", () => {
    assert.equal(projectCoverage(P, [web], [scan("p", "web", "2026-11-01T11:00:00Z", { status: "partial", complete: false })]).state, "incomplete");
    assert.equal(projectCoverage(P, [web], [scan("g", "web", "2026-11-01T11:00:00Z", { complete: false })]).state, "incomplete");
  });

  test("CI check scans never count as monitored coverage", () => {
    const coverage = projectCoverage(P, [web], [scan("check", "web", "2026-11-01T11:00:00Z", { mode: "check" })]);
    assert.equal(coverage.state, "unscanned");
  });

  test("a queued or running scan is pending", () => {
    assert.equal(projectCoverage(P, [web], [scan("q", "web", "2026-11-01T11:00:00Z", { status: "queued", complete: false })]).state, "pending");
    assert.equal(projectCoverage(P, [web], [scan("r", "web", "2026-11-01T11:00:00Z", { status: "running", complete: false })]).state, "pending");
  });

  test("superseded scans are ignored", () => {
    const scans = [scan("ok", "web", "2026-11-01T11:00:00Z"), scan("old", "web", "2026-11-01T12:00:00Z", { status: "superseded", complete: false })];
    assert.equal(projectCoverage(P, [web], scans).state, "verified");
  });

  test("verified only when every current manifest is complete", () => {
    const one = projectCoverage(P, [web, api], [scan("w", "web", "2026-11-01T11:00:00Z")]);
    assert.equal(one.state, "unscanned");
    assert.equal(one.verified, 1);
    const both = projectCoverage(P, [web, api], [scan("w", "web", "2026-11-01T11:00:00Z"), scan("a", "api", "2026-11-01T11:00:00Z")]);
    assert.equal(both.state, "verified");
    assert.equal(both.verified, 2);
  });

  test("retired manifests are left out of coverage", () => {
    const gone = inventory("gone", "old/yarn.lock", "2026-11-01T10:00:00Z", { retired_at: "2026-11-02T10:00:00Z" });
    assert.equal(projectCoverage(P, [web, gone], [scan("w", "web", "2026-11-01T11:00:00Z")]).state, "verified");
    assert.equal(projectCoverage(P, [gone], [scan("g", "gone", "2026-11-01T11:00:00Z")]).state, "none");
  });
});

describe("workspaceCoverage", () => {
  const verifiedInventory = inventory("web", "web/package-lock.json", "2026-11-01T10:00:00Z");
  const verifiedScan = scan("w", "web", "2026-11-01T11:00:00Z");

  test("no projects or only empty projects", () => {
    assert.equal(workspaceCoverage([], [], []), "none");
    assert.equal(workspaceCoverage([project(P)], [], []), "none");
  });

  test("verified only when every project is verified", () => {
    assert.equal(workspaceCoverage([project(P)], [verifiedInventory], [verifiedScan]), "verified");
    assert.equal(workspaceCoverage([project(P), project("project-2")], [verifiedInventory], [verifiedScan]), "unscanned");
  });

  test("any incomplete project makes the workspace incomplete", () => {
    const other = inventory("o", "go.mod", "2026-11-01T10:00:00Z", { project_id: "project-2" });
    const failed = scan("f", "o", "2026-11-01T11:00:00Z", { project_id: "project-2", status: "failed", complete: false });
    assert.equal(workspaceCoverage([project(P), project("project-2")], [verifiedInventory, other], [verifiedScan, failed]), "incomplete");
  });
});

describe("activity labels", () => {
  test("deliveries read as what was sent and what happened", () => {
    assert.equal(deliveryEvent("digest", "accepted"), "Daily digest delivered");
    assert.equal(deliveryEvent("test", "queued"), "Test message queued");
    assert.equal(deliveryEvent("alert", "digest_pending"), "Vulnerability alert waiting for digest");
    assert.equal(deliveryEvent("new_kind", "failed"), "New kind failed");
    assert.equal(channelLabel("telegram"), "Telegram");
    assert.equal(sentenceCase("smtp_timeout"), "Smtp timeout");
  });

  test("scans read as their outcome, naming CI checks", () => {
    const base = { id: "s", inventory_id: "i", project_id: "p", complete: true, engine_version: null, error: null, package_count: 1, coverage_notes: [], created_at: "2026-11-01T00:00:00Z", completed_at: null };
    assert.equal(scanEvent({ ...base, status: "succeeded", mode: "monitor" }), "Scan completed");
    assert.equal(scanEvent({ ...base, status: "succeeded", mode: "check" }), "CI check completed");
    assert.equal(scanEvent({ ...base, status: "succeeded", complete: false, mode: "monitor" }), "Scan completed with coverage gaps");
    assert.equal(scanEvent({ ...base, status: "running", mode: "check" }), "CI check in progress");
  });
});
