"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Icon } from "@/components/icon";
import { usePreference } from "@/components/preferences";
import { useWorkspace } from "@/components/workspace/context";
import { byPriority, primaryAdvisory } from "@/components/workspace/format";
import { Kbd, Sev } from "@/components/workspace/ui";

type Item = { id: string; group: string; title: string; detail?: string; icon: string; keywords: string; end?: ReactNode; hint?: string[]; run: () => void };

// Every term must appear; matches at the start of a word rank first.
function score(text: string, terms: string[]) {
  let total = 0;
  for (const term of terms) {
    const index = text.indexOf(term);
    if (index < 0) return -1;
    total += index === 0 ? 3 : /[\s/@._-]/.test(text[index - 1]) ? 2 : 1;
  }
  return total;
}

const GROUPS = ["Go to", "Actions", "Projects", "Findings", "Appearance"];

export function CommandPalette({ onClose, onShortcuts }: { onClose: () => void; onShortcuts: () => void }) {
  const workspace = useWorkspace();
  const router = useRouter();
  const [theme, setTheme] = usePreference("theme");
  const [density, setDensity] = usePreference("density");
  const [nav, setNav] = usePreference("nav");
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const list = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    document.body.style.overflow = "hidden";
    input.current?.focus();
    return () => { document.body.style.overflow = ""; previous?.focus?.(); };
  }, []);

  const items = useMemo(() => {
    const go = (path: string) => () => { router.push(path); };
    // Client navigation to the same page does not fire hashchange, so set the hash directly there.
    const goSection = (path: string, hash: string) => () => { if (window.location.pathname === path) window.location.hash = hash; else router.push(`${path}#${hash}`); };
    const pages: Item[] = [
      { id: "go-overview", group: "Go to", title: "Overview", icon: "grid", keywords: "dashboard home risk", hint: ["G", "O"], run: go("/") },
      { id: "go-findings", group: "Go to", title: "Findings", icon: "shield", keywords: "vulnerabilities advisories", hint: ["G", "F"], run: go("/findings") },
      { id: "go-projects", group: "Go to", title: "Projects", icon: "box", keywords: "repositories manifests", hint: ["G", "P"], run: go("/projects") },
      { id: "go-packages", group: "Go to", title: "Packages", icon: "layers", keywords: "dependencies components libraries where used search inventory", hint: ["G", "K"], run: go("/packages") },
      { id: "go-decisions", group: "Go to", title: "Decisions", icon: "check-circle", keywords: "gate pipeline ci pass fail audit", hint: ["G", "D"], run: go("/decisions") },
      { id: "go-policies", group: "Go to", title: "Policies", icon: "lock", keywords: "gate minimum enforcement rules", hint: ["G", "L"], run: go("/policies") },
      { id: "go-alerts", group: "Go to", title: "Notifications", icon: "bell", keywords: "alerts email telegram deliveries", hint: ["G", "N"], run: go("/notifications") },
      { id: "go-settings", group: "Go to", title: "Settings", icon: "settings", keywords: "ci tokens retention health", hint: ["G", "S"], run: go("/settings") },
    ];
    const actions: Item[] = [
      { id: "new-project", group: "Actions", title: "New project", icon: "plus", keywords: "create add", run: () => workspace.setModal({ kind: "project" }) },
      { id: "upload", group: "Actions", title: "Upload manifest", icon: "upload", keywords: "lockfile scan inventory", run: () => workspace.setModal({ kind: "upload" }) },
      { id: "token", group: "Actions", title: "Create CI/CD token", icon: "key", keywords: "pipeline api access", run: () => workspace.setModal({ kind: "token" }) },
      { id: "assistant-token", group: "Actions", title: "Create AI assistant token", icon: "terminal", keywords: "mcp claude chatgpt cursor ai assistant", run: () => workspace.setModal({ kind: "token", audience: "mcp" }) },
      { id: "identity", group: "Actions", title: "Add trusted CI identity", icon: "lock", keywords: "oidc github gitlab pipeline secretless", run: goSection("/settings", "identities") },
      { id: "policy", group: "Actions", title: "Edit installation policy", icon: "lock", keywords: "gate minimum enforcement rules severity", run: go("/policies") },
      { id: "refresh", group: "Actions", title: "Refresh data", icon: "refresh", keywords: "reload sync", run: () => void workspace.actions.refresh() },
      { id: "shortcuts", group: "Actions", title: "Keyboard shortcuts", icon: "keyboard", keywords: "help keys", hint: ["?"], run: onShortcuts },
      { id: "signout", group: "Actions", title: "Sign out", icon: "logout", keywords: "logout", run: () => void workspace.actions.logout() },
    ];
    const appearance: Item[] = [
      ...(["light", "dark", "system"] as const).map((value) => ({ id: `theme-${value}`, group: "Appearance", title: `Theme: ${value[0].toUpperCase()}${value.slice(1)}`, icon: value === "light" ? "sun" : value === "dark" ? "moon" : "monitor", keywords: "color mode appearance", end: theme === value ? <Icon name="check" size={14}/> : undefined, run: () => setTheme(value) })),
      ...(["comfortable", "compact"] as const).map((value) => ({ id: `density-${value}`, group: "Appearance", title: `Density: ${value[0].toUpperCase()}${value.slice(1)}`, icon: "list", keywords: "rows spacing table", end: density === value ? <Icon name="check" size={14}/> : undefined, run: () => setDensity(value) })),
      { id: "nav-toggle", group: "Appearance", title: nav === "collapsed" ? "Expand sidebar" : "Collapse sidebar", icon: "panel-left", keywords: "navigation menu", run: () => setNav(nav === "collapsed" ? "expanded" : "collapsed") },
    ];
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    const rank = (rows: Item[], limit: number) => rows
      .map((row) => ({ row, value: terms.length ? score(`${row.title} ${row.detail ?? ""} ${row.keywords}`.toLowerCase(), terms) : 0 }))
      .filter((entry) => entry.value >= 0).sort((a, b) => b.value - a.value).slice(0, limit).map((entry) => entry.row);
    if (!terms.length) return [...pages, ...actions, ...appearance];
    const projects: Item[] = workspace.projects.map((project) => ({ id: `project-${project.id}`, group: "Projects", title: project.name, detail: project.description.replace(/\s*\(Demo data\.\)$/, "") || undefined, icon: "box", keywords: "", run: () => workspace.setProjectId(project.id) }));
    const names = new Map(workspace.projects.map((project) => [project.id, project.name]));
    const findings: Item[] = workspace.findings.filter((finding) => finding.status === "open").sort(byPriority).map((finding) => ({
      id: `finding-${finding.id}`, group: "Findings", title: `${finding.package_name}@${finding.package_version}`, detail: `${names.get(finding.project_id) ?? "Project"} · ${primaryAdvisory(finding.advisory_ids)}`,
      icon: "shield", keywords: `${finding.advisory_ids.join(" ")} ${finding.summary} ${finding.ecosystem}`, end: <Sev value={finding.severity}/>, run: () => workspace.setFindingId(finding.id),
    }));
    return [...rank(pages, 5), ...rank(actions, 6), ...rank(projects, 5), ...rank(findings, 8), ...rank(appearance, 4)];
  }, [query, workspace, router, theme, density, nav, setTheme, setDensity, setNav, onShortcuts]);

  const groups = GROUPS.map((group) => ({ group, rows: items.filter((item) => item.group === group) })).filter((entry) => entry.rows.length);
  const flat = groups.flatMap((entry) => entry.rows);
  const active = Math.min(index, Math.max(flat.length - 1, 0));

  useEffect(() => { list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" }); }, [active, query]);

  function run(item: Item | undefined) {
    if (!item) return;
    onClose();
    item.run();
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === "Escape") { event.preventDefault(); onClose(); }
    else if (event.key === "ArrowDown") { event.preventDefault(); setIndex((active + 1) % Math.max(flat.length, 1)); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setIndex((active - 1 + flat.length) % Math.max(flat.length, 1)); }
    else if (event.key === "Enter") { event.preventDefault(); run(flat[active]); }
  }

  return (
    <div className="palette-layer" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={onKeyDown}>
        <div className="palette-input">
          <Icon name="search" size={17}/>
          <input ref={input} value={query} onChange={(event) => { setQuery(event.target.value); setIndex(0); }} placeholder="Search findings, projects, or type a command…" role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={flat[active] ? `palette-${flat[active].id}` : undefined} aria-label="Command palette search" autoComplete="off" spellCheck={false}/>
          <Kbd>Esc</Kbd>
        </div>
        <div className="palette-list" id="palette-list" role="listbox" ref={list}>
          {groups.map(({ group, rows }) => (
            <div key={group} role="group" aria-label={group}>
              <div className="palette-group">{group}</div>
              {rows.map((item) => {
                const selected = flat[active]?.id === item.id;
                return (
                  <button key={item.id} id={`palette-${item.id}`} type="button" role="option" aria-selected={selected} className="palette-item" tabIndex={-1} onMouseMove={() => setIndex(flat.indexOf(item))} onClick={() => run(item)}>
                    <Icon name={item.icon} size={16}/>
                    <span className="palette-text"><b>{item.title}</b>{item.detail && <small>{item.detail}</small>}</span>
                    {item.end}
                    {item.hint && <span className="palette-hint">{item.hint.map((key) => <Kbd key={key}>{key}</Kbd>)}</span>}
                  </button>
                );
              })}
            </div>
          ))}
          {!flat.length && <div className="palette-empty">No results for “{query}”.</div>}
        </div>
        <div className="palette-foot"><span><Kbd>↑</Kbd><Kbd>↓</Kbd>navigate</span><span><Kbd>↵</Kbd>select</span><span><Kbd>Esc</Kbd>close</span></div>
      </div>
    </div>
  );
}
