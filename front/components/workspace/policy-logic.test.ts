import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { DecisionActor, DecisionSummary, PolicyRules } from "../../lib/api.ts";
import { actorLabel, DEFAULT_RULES, describeChanges, epssProblem, eventLabel, floorLocks, intelligenceAge, isPermissive, matchesDecision, mergeRules, normalizeRef, normalizeRules, outcomeText, policyLabel, refLabel, reportFile, repositoryProblem, revisionLabel, rulesEqual, statusCounts, stricterEpss, stricterThreshold, summarizeGate, summarizeRules, thresholdStrictness } from "./policy-logic.ts";

const rules = (patch: Partial<PolicyRules>): PolicyRules => ({ ...DEFAULT_RULES, ...patch });
const actor = (patch: Partial<DecisionActor>): DecisionActor => ({ kind: "token", name: "acme CI", token_id: "t1", verified: false, provider: null, repository: null, workflow: null, ref: null, event: null, run_id: null, run_url: null, ...patch });
const decision = (patch: Partial<DecisionSummary>): DecisionSummary => ({
  id: "0f3c9a10-0000-4000-8000-000000000000", created_at: "2026-11-05T10:00:00Z", status: "pass", project_id: "p1", project_name: "acme-storefront",
  revision: "main@abc123def456", commit: null, mode: "monitor", violations: 0, ignored: 0, below_threshold: 0, missing_manifests: 0,
  actor: actor({}), policy_sources: [], adjustments: 0, ...patch,
});

describe("strictness", () => {
  test("a lower severity threshold is stricter and none is the least strict", () => {
    const order = ["none", "critical", "high", "medium", "low"] as const;
    for (let index = 1; index < order.length; index += 1) assert.ok(thresholdStrictness(order[index]) > thresholdStrictness(order[index - 1]), order[index]);
    assert.equal(stricterThreshold("critical", "high"), "high");
    assert.equal(stricterThreshold("medium", "high"), "medium");
    assert.equal(stricterThreshold("none", "critical"), "critical");
    assert.equal(stricterThreshold("none", "none"), "none");
  });

  test("the lower EPSS threshold wins and null never relaxes a set value", () => {
    assert.equal(stricterEpss(0.2, 0.1), 0.1);
    assert.equal(stricterEpss(null, 0.3), 0.3);
    assert.equal(stricterEpss(0.3, null), 0.3);
    assert.equal(stricterEpss(null, null), null);
  });
});

describe("mergeRules", () => {
  test("every rule takes the stricter layer, so a project cannot relax the installation", () => {
    const installation = rules({ fail_on: "high", fail_on_kev: true, epss_threshold: 0.2, allow_new_only: false });
    const project = rules({ fail_on: "critical", fail_on_incomplete: true, epss_threshold: 0.5, allow_new_only: true, allow_ignore_acknowledged: false });
    assert.deepEqual(mergeRules(installation, project), {
      fail_on: "high", fail_on_unknown: false, fail_on_kev: true, epss_threshold: 0.2, fail_on_incomplete: true,
      require_monitored_manifests: false, allow_new_only: false, allow_ignore_acknowledged: false,
    });
  });

  test("merging is symmetric and a missing override changes nothing", () => {
    const a = rules({ fail_on: "medium", fail_on_unknown: true });
    const b = rules({ fail_on: "high", require_monitored_manifests: true, epss_threshold: 0.4 });
    assert.deepEqual(mergeRules(a, b), mergeRules(b, a));
    assert.deepEqual(mergeRules(a, null), a);
    assert.notEqual(mergeRules(a, null), a, "returns a copy");
  });

  test("defaults merge to defaults", () => {
    assert.ok(isPermissive(mergeRules(DEFAULT_RULES, DEFAULT_RULES)));
    assert.ok(!isPermissive(rules({ allow_new_only: false })));
  });
});

describe("normalizeRules and rulesEqual", () => {
  test("missing rules from an older API fall back to the permissive defaults", () => {
    assert.deepEqual(normalizeRules({ fail_on: "high" }), rules({ fail_on: "high" }));
    assert.deepEqual(normalizeRules(null), DEFAULT_RULES);
  });

  test("compares every rule and treats null as no override", () => {
    assert.ok(rulesEqual(rules({}), rules({})));
    assert.ok(!rulesEqual(rules({}), rules({ epss_threshold: 0.1 })));
    assert.ok(rulesEqual(null, null));
    assert.ok(!rulesEqual(null, rules({})));
  });
});

describe("floorLocks", () => {
  test("locks the rules the installation already enforces", () => {
    const locks = floorLocks(rules({ fail_on: "high", fail_on_kev: true, allow_ignore_acknowledged: false, epss_threshold: 0.3 }));
    assert.deepEqual(locks.thresholds, ["none", "critical"]);
    assert.equal(locks.fail_on_kev, true);
    assert.equal(locks.fail_on_unknown, false);
    assert.equal(locks.allow_ignore_acknowledged, true);
    assert.equal(locks.allow_new_only, false);
    assert.equal(locks.epss, true);
    assert.equal(locks.epssMax, 0.3);
  });

  test("a permissive floor locks nothing", () => {
    const locks = floorLocks(DEFAULT_RULES);
    assert.deepEqual(locks.thresholds, []);
    assert.equal(Object.entries(locks).filter(([key, value]) => key !== "thresholds" && key !== "epssMax" && value).length, 0);
  });

  test("a low floor leaves only low available", () => {
    assert.deepEqual(floorLocks(rules({ fail_on: "low" })).thresholds, ["none", "medium", "high", "critical"]);
  });
});

describe("epssProblem", () => {
  test("accepts probabilities, rejects out-of-range values and values looser than the floor", () => {
    assert.equal(epssProblem(null), null);
    assert.equal(epssProblem(0.25), null);
    assert.match(epssProblem(1.2) ?? "", /between 0 and 1/);
    assert.match(epssProblem(Number.NaN) ?? "", /between 0 and 1/);
    assert.match(epssProblem(0.5, 0.3) ?? "", /0\.3 or lower/);
    assert.equal(epssProblem(0.3, 0.3), null);
  });
});

describe("summaries", () => {
  test("reads a rule set in one line", () => {
    assert.equal(summarizeRules(rules({ fail_on: "high", fail_on_kev: true, fail_on_incomplete: true })), "High and above · KEV · complete coverage");
    assert.equal(summarizeRules(DEFAULT_RULES), "No central requirements");
    assert.equal(summarizeRules(rules({ fail_on: "critical" })), "Critical only");
    assert.equal(summarizeRules(rules({ fail_on_kev: true, epss_threshold: 0.1 })), "KEV · EPSS ≥ 0.1");
    // Unknown severity only matters with a severity threshold.
    assert.equal(summarizeRules(rules({ fail_on_unknown: true })), "No central requirements");
    assert.equal(summarizeRules(rules({ allow_new_only: false, require_monitored_manifests: true })), "Every manifest · no new-only");
  });

  test("describes the gate a decision enforced", () => {
    const gate = { fail_on: "medium", fail_on_unknown: false, fail_on_kev: true, epss_threshold: null, new_only: true, ignore_acknowledged: false, fail_on_incomplete: false, require_monitored_manifests: false } as const;
    assert.equal(summarizeGate(gate), "Medium and above · KEV · new findings only");
  });

  test("describes what changed between versions", () => {
    assert.deepEqual(describeChanges(rules({ fail_on: "critical" }), rules({ fail_on: "high", fail_on_kev: true })), ["Minimum severity: critical → high", "Known exploited (KEV): off → on"]);
    assert.deepEqual(describeChanges(null, rules({ allow_new_only: false })), ["New-only gating: allowed → not allowed"]);
    assert.deepEqual(describeChanges(rules({ epss_threshold: 0.2 }), null), ["Override removed; the installation policy applies"]);
    assert.deepEqual(describeChanges(rules({}), rules({})), ["No rule changes"]);
    assert.deepEqual(describeChanges(null, DEFAULT_RULES), ["Saved with no requirements"]);
  });
});

describe("decision formatting", () => {
  test("labels the actor by token, owner, or verified repository", () => {
    assert.equal(actorLabel(actor({})), "acme CI");
    assert.equal(actorLabel(actor({ kind: "owner", name: "Owner" })), "Owner");
    assert.equal(actorLabel(actor({ kind: "identity", verified: true, provider: "github", repository: "acme/storefront" })), "GitHub · acme/storefront");
    assert.equal(actorLabel(actor({ kind: "identity", provider: "gitlab", repository: "acme/web/api" })), "GitLab · acme/web/api");
  });

  test("prefers the revision label and falls back to the short commit", () => {
    assert.equal(revisionLabel({ revision: "main@abc123def456", commit: "f".repeat(40) }), "main@abc123def456");
    assert.equal(revisionLabel({ revision: null, commit: "0123456789abcdef0123" }), "0123456789ab");
    assert.equal(revisionLabel({ revision: null, commit: null }), "—");
  });

  test("reads refs and events", () => {
    assert.equal(refLabel("refs/heads/main"), "main");
    assert.equal(refLabel("refs/pull/12/merge"), "PR #12");
    assert.equal(refLabel("refs/tags/v1.2.0"), "tag v1.2.0");
    assert.equal(refLabel(null), "—");
    assert.equal(eventLabel("merge_request_event"), "Merge request");
    assert.equal(eventLabel("deployment_status"), "Deployment status");
  });

  test("names policy versions, installation first", () => {
    assert.equal(policyLabel([{ scope: "project", project_id: "p1", version: 1, policy_id: "b" }, { scope: "installation", project_id: null, version: 3, policy_id: "a" }]), "Installation v3 · Project v1");
    assert.equal(policyLabel([{ scope: "installation", project_id: null, version: 0, policy_id: null }]), "Installation default");
    assert.equal(policyLabel([]), "Pipeline only");
  });

  test("searches project, revision, commit, and actor", () => {
    const row = decision({ commit: "deadbeefcafe0000", actor: actor({ kind: "identity", provider: "github", repository: "acme/storefront", workflow: ".github/workflows/ci.yml" }) });
    assert.ok(matchesDecision(row, "storefront main"));
    assert.ok(matchesDecision(row, "DEADBEEF"));
    assert.ok(matchesDecision(row, "github ci.yml"));
    assert.ok(!matchesDecision(row, "storefront develop"));
    assert.ok(matchesDecision(row, "  "));
  });

  test("counts by status", () => {
    assert.deepEqual(statusCounts([decision({}), decision({ status: "fail" }), decision({ status: "fail" }), decision({ status: "error" })]), { all: 4, pass: 1, fail: 2, error: 1 });
  });

  test("summarizes the outcome", () => {
    assert.equal(outcomeText(decision({ status: "fail", violations: 3, missing_manifests: 1, ignored: 2 })), "3 violations · 1 manifest missing");
    assert.equal(outcomeText(decision({ status: "fail", missing_manifests: 2 })), "2 manifests missing");
    assert.equal(outcomeText(decision({})), "No violations");
    assert.equal(outcomeText(decision({ status: "error" })), "Could not evaluate");
  });

  test("states how old the threat intelligence was at decision time", () => {
    assert.match(intelligenceAge("2026-11-05T10:00:00Z", null), /had not been refreshed/);
    assert.match(intelligenceAge("2026-11-05T10:00:00Z", "2026-11-05T09:30:00Z"), /under an hour old/);
    assert.match(intelligenceAge("2026-11-05T10:00:00Z", "2026-11-04T07:00:00Z"), /27 hours old/);
    assert.match(intelligenceAge("2026-11-05T10:00:00Z", "2026-11-01T10:00:00Z"), /4 days old/);
  });

  test("names report downloads by format", () => {
    assert.deepEqual(reportFile("0f3c9a10-aaaa", "sarif"), { name: "depradar-0f3c9a10.sarif", type: "application/sarif+json" });
    assert.equal(reportFile("0f3c9a10-aaaa", "junit").name, "depradar-0f3c9a10.xml");
    assert.equal(reportFile("0f3c9a10-aaaa", "markdown").name, "depradar-0f3c9a10.md");
  });
});

describe("identity input", () => {
  test("expands branch names to refs", () => {
    assert.equal(normalizeRef("main"), "refs/heads/main");
    assert.equal(normalizeRef(" refs/heads/release "), "refs/heads/release");
    assert.equal(normalizeRef(""), null);
  });

  test("validates repository paths per provider", () => {
    assert.equal(repositoryProblem("github", "acme/storefront"), null);
    assert.match(repositoryProblem("github", "acme/web/storefront") ?? "", /owner\/name/);
    assert.equal(repositoryProblem("gitlab", "acme/web/storefront"), null);
    assert.match(repositoryProblem("gitlab", "storefront") ?? "", /group\/project/);
    assert.match(repositoryProblem("github", "https://github.com/acme/x") ?? "", /without spaces or a host/);
    assert.match(repositoryProblem("github", "") ?? "", /Enter/);
  });
});
