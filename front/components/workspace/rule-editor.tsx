"use client";

import { Icon } from "@/components/icon";
import { epssProblem, floorLocks, mergeRules, THRESHOLD_LABEL, thresholdText, type AllowRule, type RequireRule } from "@/components/workspace/policy-logic";
import { Switch } from "@/components/workspace/ui";
import type { PolicyRules, Threshold } from "@/lib/api";
import "./rule-editor.css";

const REQUIRE_COPY: Record<RequireRule, { title: string; detail: string }> = {
  fail_on_kev: { title: "Known exploited vulnerabilities", detail: "Fail on any vulnerability in CISA’s Known Exploited Vulnerabilities (KEV) catalog, the list of flaws attackers are actively using, whatever its severity." },
  fail_on_unknown: { title: "Unknown severity", detail: "Fail on vulnerabilities whose advisory gives no severity rating." },
  fail_on_incomplete: { title: "Complete coverage", detail: "Fail when the scanner cannot check every package, for example packages from a private registry or without an exact version." },
  require_monitored_manifests: { title: "Every monitored manifest", detail: "Fail when the pipeline run does not scan every manifest DepRadar monitors for the project." },
};
const ALLOW_COPY: Record<AllowRule, { title: string; detail: string }> = {
  allow_new_only: { title: "Check new findings only", detail: "Lets a pipeline use --new-only, so only vulnerabilities the change introduces can fail it. Findings already open in the project are ignored." },
  allow_ignore_acknowledged: { title: "Ignore acknowledged findings", detail: "Lets a pipeline use --ignore-acknowledged, so acknowledged findings do not fail it. Findings with accepted risk never fail it until the acceptance expires." },
};
// Severity choices read from least to most strict.
const ORDER: Threshold[] = ["none", "critical", "high", "medium", "low"];

function Locked() {
  return <span className="tag tag-muted rule-lock"><Icon name="lock" size={11}/>Set by the global policy</span>;
}

/**
 * Edits one policy layer. With a `floor` (the installation rules, when editing a project policy),
 * the controls show the effective value and options weaker than the floor are locked: a project
 * can only add requirements. `value` stays the layer's own rules, so the floor is never copied in.
 */
export function RuleEditor({ value, onChange, floor, idPrefix, autoFocus = false }: { value: PolicyRules; onChange: (next: PolicyRules) => void; floor?: PolicyRules; idPrefix: string; autoFocus?: boolean }) {
  const effective = floor ? mergeRules(floor, value) : value;
  const locks = floor ? floorLocks(floor) : null;
  const set = <K extends keyof PolicyRules>(key: K, next: PolicyRules[K]) => onChange({ ...value, [key]: next });
  const epssMax = locks?.epssMax ?? null;
  const epss = effective.epss_threshold;
  const epssError = epssProblem(value.epss_threshold, epssMax);
  const severityId = `${idPrefix}-severity`;

  return (
    <div className="rule-editor">
      <div className="field">
        <span className="field-label" id={severityId}>Fail on severity</span>
        <div className="seg rule-seg" role="group" aria-labelledby={severityId}>
          {ORDER.map((option) => {
            const locked = locks?.thresholds.includes(option) ?? false;
            return (
              <button key={option} type="button" aria-pressed={effective.fail_on === option} data-autofocus={autoFocus && effective.fail_on === option ? true : undefined} disabled={locked} title={locked ? "Less strict than the global policy" : undefined} onClick={() => set("fail_on", option)}>
                {THRESHOLD_LABEL[option]}
              </button>
            );
          })}
        </div>
        <span className="field-hint">{thresholdText(effective.fail_on)}.{floor && locks && locks.thresholds.length > 0 ? ` The global policy requires ${thresholdText(floor.fail_on).toLowerCase()}, so less strict options are unavailable.` : ""}</span>
      </div>

      <div className="rule-group" role="group" aria-label="Always fail on">
        <span className="rule-group-title">Always fail on</span>
        {(["fail_on_kev", "fail_on_unknown", "fail_on_incomplete", "require_monitored_manifests"] as const).map((key) => {
          const locked = locks?.[key] ?? false;
          return (
            <div className="toggle-row" key={key}>
              <span><b>{REQUIRE_COPY[key].title}{locked && <Locked/>}</b><small>{REQUIRE_COPY[key].detail}</small></span>
              <Switch checked={effective[key]} disabled={locked} label={REQUIRE_COPY[key].title} onChange={(checked) => set(key, checked)}/>
            </div>
          );
        })}
        <div className="toggle-row rule-epss">
          <span>
            <b>EPSS threshold{locks?.epss && <Locked/>}</b>
            <small>Fail when a vulnerability’s EPSS score, the estimated probability that it is exploited in the next 30 days, reaches this value.</small>
            {epss !== null && (
              <span className="rule-epss-field">
                <label htmlFor={`${idPrefix}-epss`} className="sr-only">EPSS threshold, 0 to 1</label>
                <input id={`${idPrefix}-epss`} className="input mono" type="number" min={0} max={epssMax ?? 1} step={0.01} inputMode="decimal" aria-invalid={Boolean(epssError)} aria-describedby={epssError ? `${idPrefix}-epss-error` : undefined}
                  value={Number.isFinite(epss) ? epss : ""} onChange={(event) => set("epss_threshold", event.target.value === "" ? Number.NaN : event.target.valueAsNumber)}/>
                <span className="muted num">{Number.isFinite(epss) ? `${(epss * 100).toFixed(epss < 0.1 ? 1 : 0)}% chance` : ""}</span>
              </span>
            )}
            {epssError && <span className="field-error" id={`${idPrefix}-epss-error`}><Icon name="warning" size={13}/>{epssError}</span>}
          </span>
          <Switch checked={epss !== null} disabled={locks?.epss ?? false} label="EPSS threshold" onChange={(checked) => set("epss_threshold", checked ? epssMax ?? 0.1 : null)}/>
        </div>
      </div>

      <div className="rule-group" role="group" aria-label="Pipelines may">
        <span className="rule-group-title">Pipelines may</span>
        {(["allow_new_only", "allow_ignore_acknowledged"] as const).map((key) => {
          const locked = locks?.[key] ?? false;
          return (
            <div className="toggle-row" key={key}>
              <span><b>{ALLOW_COPY[key].title}{locked && <Locked/>}</b><small>{ALLOW_COPY[key].detail}</small></span>
              <Switch checked={effective[key]} disabled={locked} label={`Pipelines may ${ALLOW_COPY[key].title.toLowerCase()}`} onChange={(checked) => set(key, checked)}/>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Null when the layer can be saved, otherwise the reason it cannot. */
export function rulesProblem(value: PolicyRules, floor?: PolicyRules): string | null {
  return epssProblem(value.epss_threshold, floor?.epss_threshold ?? null);
}
