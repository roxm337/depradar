"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Brand } from "@/components/auth-shell";
import { Icon } from "@/components/icon";
import { usePreference, useSystemThemeSync } from "@/components/preferences";
import { useWorkspace } from "@/components/workspace/context";
import { relativeTime, severityOf } from "@/components/workspace/format";
import { CommandPalette } from "@/components/workspace/palette";
import { Kbd, Menu, MenuItem, Modal } from "@/components/workspace/ui";

const navigation = [
  { group: "Monitor", items: [{ href: "/", label: "Overview", icon: "grid", key: "o" }, { href: "/findings", label: "Findings", icon: "shield", key: "f" }, { href: "/projects", label: "Projects", icon: "box", key: "p" }, { href: "/packages", label: "Packages", icon: "layers", key: "k" }, { href: "/decisions", label: "Decisions", icon: "check-circle", key: "d" }] },
  { group: "Configure", items: [{ href: "/policies", label: "Policies", icon: "lock", key: "l" }, { href: "/notifications", label: "Notifications", icon: "bell", key: "n" }, { href: "/settings", label: "Settings", icon: "settings", key: "s" }] },
];
const pages = navigation.flatMap((section) => section.items);
const shortcuts: Array<{ label: string; keys: string[] }> = [
  { label: "Command palette", keys: ["⌘", "K"] },
  { label: "Search the page", keys: ["/"] },
  { label: "This help", keys: ["?"] },
  { label: "Go to Overview", keys: ["G", "O"] },
  { label: "Go to Findings", keys: ["G", "F"] },
  { label: "Go to Projects", keys: ["G", "P"] },
  { label: "Go to Packages", keys: ["G", "K"] },
  { label: "Go to Decisions", keys: ["G", "D"] },
  { label: "Go to Policies", keys: ["G", "L"] },
  { label: "Go to Notifications", keys: ["G", "N"] },
  { label: "Go to Settings", keys: ["G", "S"] },
  { label: "Next / previous finding", keys: ["J", "K"] },
  { label: "Open the finding", keys: ["↵"] },
  { label: "Select the finding", keys: ["X"] },
  { label: "Acknowledge selection", keys: ["A"] },
  { label: "Clear selection / close", keys: ["Esc"] },
];

function typing(target: EventTarget | null) {
  return target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
}

export function Shell({ children }: { children: ReactNode }) {
  const workspace = useWorkspace();
  const { findings, projects, deliveries, health, notice } = workspace;
  const pathname = usePathname();
  const router = useRouter();
  const [railOpen, setRailOpen] = useState(false);
  const [palette, setPalette] = useState(false);
  const [help, setHelp] = useState(false);
  const [theme, setTheme] = usePreference("theme");
  const [density, setDensity] = usePreference("density");
  const [nav, setNav] = usePreference("nav");
  const chord = useRef<number | null>(null);
  useSystemThemeSync();

  const open = findings.filter((finding) => finding.status === "open");
  const urgent = open.some((finding) => ["critical", "high"].includes(severityOf(finding.severity)) && finding.workflow_status === "open");
  const failedDeliveries = deliveries.filter((delivery) => delivery.status === "failed").length;
  const counts: Record<string, number | undefined> = { "/findings": open.length, "/projects": projects.length };
  const services = [
    { label: "API", state: workspace.error ? "Degraded" : "Online", ok: !workspace.error },
    { label: "Worker", state: health ? (health.worker === "healthy" ? "Running" : "Not reporting") : "Unknown", ok: health?.worker === "healthy" },
    { label: "Scanner", state: health ? (health.scanner === "healthy" ? "Ready" : health.scanner === "unavailable" ? "Unavailable" : "Not reporting") : "Unknown", ok: health?.scanner === "healthy" },
  ];
  const problems = services.filter((service) => !service.ok && service.state !== "Unknown");
  const summary = !health ? "Checking services…" : problems.length ? `${problems.map((service) => service.label).join(", ")} ${problems.length === 1 ? "needs" : "need"} attention` : "All systems operational";
  const current = pages.find((page) => (page.href === "/" ? pathname === "/" : pathname.startsWith(page.href)));
  const openPalette = useCallback(() => { setHelp(false); setPalette(true); }, []);
  const showHelp = useCallback(() => { setPalette(false); setHelp(true); }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) { event.preventDefault(); setPalette((value) => !value); return; }
      if (event.metaKey || event.ctrlKey || event.altKey || typing(event.target)) return;
      if (event.key === "/") {
        event.preventDefault();
        const field = document.querySelector<HTMLInputElement>("[data-page-search]");
        if (field) field.focus(); else openPalette();
      } else if (event.key === "?") { event.preventDefault(); showHelp(); }
      else if (chord.current !== null) {
        window.clearTimeout(chord.current); chord.current = null;
        const target = pages.find((page) => page.key === event.key.toLowerCase());
        if (target) { event.preventDefault(); router.push(target.href); }
      } else if (event.key === "g") {
        chord.current = window.setTimeout(() => { chord.current = null; }, 900);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openPalette, showHelp, router]);

  return (
    <div className="app">
      <a className="skip-link" href="#content">Skip to content</a>
      <nav className={`nav ${railOpen ? "is-open" : ""}`} aria-label="Main navigation">
        <div className="nav-top">
          <Brand/>
          <button className="nav-collapse" onClick={() => setNav(nav === "collapsed" ? "expanded" : "collapsed")} aria-label={nav === "collapsed" ? "Expand sidebar" : "Collapse sidebar"} title={nav === "collapsed" ? "Expand sidebar" : "Collapse sidebar"}><Icon name="panel-left" size={16}/></button>
        </div>
        {navigation.map((section) => (
          <div className="nav-group" key={section.group}>
            <span className="nav-label">{section.group}</span>
            {section.items.map((item) => {
              const active = item === current;
              const count = counts[item.href];
              return (
                <Link key={item.href} href={item.href} className={`nav-link ${active ? "is-active" : ""}`} aria-current={active ? "page" : undefined} title={item.label} onClick={() => setRailOpen(false)}>
                  <Icon name={item.icon} size={16}/><span>{item.label}</span>
                  {count !== undefined && workspace.ready && <span className={`nav-count ${item.href === "/findings" && urgent ? "is-hot" : ""}`}>{count}</span>}
                  {item.href === "/notifications" && failedDeliveries > 0 && <span className="nav-count is-hot" aria-label={`${failedDeliveries} failed deliveries`}>{failedDeliveries}</span>}
                </Link>
              );
            })}
          </div>
        ))}
        <div className="nav-foot">
          <Menu label="Service status" up align="left" trigger={({ props }) => (
            <button className="nav-status" {...props} title={summary}><span className={`dot ${problems.length ? "dot-warn" : health ? "dot-ok" : ""}`}/><span>{summary}</span></button>
          )}>
            {(close) => (
              <>
                <div className="menu-heading">Services</div>
                {services.map((service) => <div className="menu-item" key={service.label} role="presentation"><span className={`dot ${service.ok ? "dot-ok" : service.state === "Unknown" ? "" : "dot-warn"}`}/>{service.label}<span className="menu-end">{service.state}</span></div>)}
                <div className="menu-sep"/>
                <MenuItem icon="activity" onSelect={() => { close(); router.push("/settings#health"); }}>Open health details</MenuItem>
              </>
            )}
          </Menu>
          <Menu label="Account" up align="left" trigger={({ props }) => (
            <button className="nav-user" {...props} title="Account and preferences"><span className="avatar">OW</span><span><b>Owner</b><small>Preferences</small></span><Icon name="chevron-up" size={14}/></button>
          )}>
            {(close) => (
              <>
                <div className="menu-heading">Theme</div>
                {([["light", "Light", "sun"], ["dark", "Dark", "moon"], ["system", "System", "monitor"]] as const).map(([value, label, icon]) => <MenuItem key={value} icon={icon} checked={theme === value} onSelect={() => setTheme(value)}>{label}</MenuItem>)}
                <div className="menu-sep"/>
                <div className="menu-heading">Table density</div>
                {([["comfortable", "Comfortable"], ["compact", "Compact"]] as const).map(([value, label]) => <MenuItem key={value} icon="list" checked={density === value} onSelect={() => setDensity(value)}>{label}</MenuItem>)}
                <div className="menu-sep"/>
                <MenuItem icon="keyboard" end={<Kbd>?</Kbd>} onSelect={() => { close(); showHelp(); }}>Keyboard shortcuts</MenuItem>
                <MenuItem icon="logout" danger onSelect={() => { close(); void workspace.actions.logout(); }}>Sign out</MenuItem>
              </>
            )}
          </Menu>
        </div>
      </nav>
      {railOpen && <div className="scrim" onClick={() => setRailOpen(false)}/>}
      <div className="main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setRailOpen(true)} aria-label="Open navigation"><Icon name="menu"/></button>
          <div className="crumbs"><span className="crumb-root">DepRadar</span><Icon name="chevron" size={13}/><b>{current?.label ?? "DepRadar"}</b></div>
          <button className="search-trigger" onClick={openPalette} aria-label="Search or run a command" aria-keyshortcuts="Control+K Meta+K"><Icon name="search" size={15}/><span>Search or jump to…</span><Kbd>⌘K</Kbd></button>
          <div className="topbar-right">
            <span className="sync">{workspace.syncedAt ? <>Synced {relativeTime(workspace.now, workspace.syncedAt)}</> : "Syncing…"}</span>
            <button className={`icon-btn ${workspace.loading ? "is-spinning" : ""}`} onClick={() => void workspace.actions.refresh()} aria-label="Refresh workspace" title="Refresh"><Icon name="refresh" size={16}/></button>
            <Link className="icon-btn" href="/notifications" aria-label={failedDeliveries ? `${failedDeliveries} failed deliveries` : "Notifications"} title="Notifications"><Icon name="bell" size={16}/>{failedDeliveries > 0 && <i className="badge-dot"/>}</Link>
          </div>
          {workspace.loading && <span className="progress" aria-hidden="true"/>}
        </header>
        <main className="page" id="content" tabIndex={-1}>
          {workspace.error && <div className="banner" role="alert"><Icon name="warning" size={16}/>Refresh failed: {workspace.error}. Data may be out of date.<button onClick={() => void workspace.actions.refresh()}>Retry</button></div>}
          {workspace.upgradeHint && <div className="banner" role="status"><Icon name="warning" size={16}/>The API runs an older build, so manifest freshness is unavailable. Rebuild with <code className="inline-code">docker compose up --build -d api worker</code>.</div>}
          {children}
        </main>
      </div>
      {palette && <CommandPalette onClose={() => setPalette(false)} onShortcuts={showHelp}/>}
      {help && (
        <Modal title="Keyboard shortcuts" description="Available anywhere unless a text field has focus." onClose={() => setHelp(false)}>
          <div className="modal-body"><div className="shortcuts">{shortcuts.map((shortcut) => <div className="shortcut" key={shortcut.label}>{shortcut.label}<span>{shortcut.keys.map((key) => <Kbd key={key}>{key}</Kbd>)}</span></div>)}</div></div>
          <div className="modal-foot"><button className="btn btn-secondary" onClick={() => setHelp(false)}>Close</button></div>
        </Modal>
      )}
      {notice && <div className={`toast is-${notice.kind}`} role={notice.kind === "error" ? "alert" : "status"}><span className="toast-mark"><Icon name={notice.kind === "error" ? "warning" : notice.kind === "info" ? "clock" : "check"} size={11}/></span><span>{notice.text}</span><button onClick={() => workspace.setNotice(null)} aria-label="Dismiss"><Icon name="close" size={14}/></button></div>}
    </div>
  );
}
