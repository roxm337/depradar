"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Brand } from "@/components/auth-shell";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { relativeTime, severityOf } from "@/components/workspace/format";

const navigation = [
  { group: "Monitor", items: [{ href: "/", label: "Overview", icon: "grid" }, { href: "/findings", label: "Findings", icon: "shield" }, { href: "/projects", label: "Projects", icon: "box" }] },
  { group: "Configure", items: [{ href: "/notifications", label: "Notifications", icon: "bell" }, { href: "/settings", label: "Settings", icon: "settings" }] },
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
  const search = useRef<HTMLInputElement>(null);
  const open = findings.filter((finding) => finding.status === "open");
  const urgent = open.some((finding) => ["critical", "high"].includes(severityOf(finding.severity)) && finding.workflow_status === "open");
  const failedDeliveries = deliveries.filter((delivery) => delivery.status === "failed").length;
  const counts: Record<string, number | undefined> = { "/findings": open.length, "/projects": projects.length };
  const services = [
    { label: "API", state: workspace.error ? "Degraded" : "Online", tone: workspace.error ? "dot-warn" : "dot-ok dot-live" },
    { label: "Worker", state: health ? (health.worker === "healthy" ? "Running" : "Stale") : "—", tone: health?.worker === "healthy" ? "dot-ok" : "dot-warn" },
    { label: "Scanner", state: health ? (health.scanner === "healthy" ? "Ready" : health.scanner === "unavailable" ? "Down" : "Stale") : "—", tone: health?.scanner === "healthy" ? "dot-ok" : health?.scanner === "unavailable" ? "dot-bad" : "dot-warn" },
  ];

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.key === "k" && (event.metaKey || event.ctrlKey)) || (event.key === "/" && !typing(event.target))) { event.preventDefault(); search.current?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="app">
      <nav className={`rail ${railOpen ? "is-open" : ""}`} aria-label="Main navigation">
        <div className="rail-top"><Brand/><button className="rail-close" onClick={() => setRailOpen(false)} aria-label="Close navigation"><Icon name="close"/></button></div>
        {navigation.map((section) => (
          <div className="rail-group" key={section.group}>
            <span className="rail-label">{section.group}</span>
            {section.items.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              const count = counts[item.href];
              return <Link key={item.href} href={item.href} className={`rail-link ${active ? "is-active" : ""}`} aria-current={active ? "page" : undefined} onClick={() => setRailOpen(false)}><Icon name={item.icon} size={17}/>{item.label}{count !== undefined && workspace.ready && <span className={`rail-count ${item.href === "/findings" && urgent ? "is-hot" : ""}`}>{count}</span>}{item.href === "/notifications" && failedDeliveries > 0 && <span className="rail-count is-hot">{failedDeliveries}</span>}</Link>;
            })}
          </div>
        ))}
        <div className="rail-foot">
          <div className="rail-health" aria-label="Service status">{services.map((service) => <div className="rail-health-row" key={service.label}><span className={`dot ${service.tone}`}/>{service.label}<b>{service.state}</b></div>)}</div>
          <button className="rail-user" onClick={() => void workspace.actions.logout()}><span className="avatar">OW</span><span>Owner<small>Sign out</small></span><Icon name="logout" size={16}/></button>
        </div>
      </nav>
      {railOpen && <div className="scrim" onClick={() => setRailOpen(false)}/>}
      <div className="main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setRailOpen(true)} aria-label="Open navigation"><Icon name="menu"/></button>
          <label className="search">
            <Icon name="search" size={16}/>
            <input ref={search} type="search" placeholder="Search packages, advisories, projects…" aria-label="Search findings" value={workspace.query} onChange={(event) => workspace.setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && pathname !== "/findings") router.push("/findings"); }}/>
            <kbd>⌘K</kbd>
          </label>
          <div className="topbar-right">
            <span className="sync">{workspace.syncedAt ? <>Synced {relativeTime(workspace.now, workspace.syncedAt)}</> : "Syncing…"}</span>
            <button className={`icon-btn ${workspace.loading ? "is-spinning" : ""}`} onClick={() => void workspace.actions.refresh()} aria-label="Refresh workspace" title="Refresh"><Icon name="refresh" size={17}/></button>
            <Link className="icon-btn" href="/notifications" aria-label={failedDeliveries ? `${failedDeliveries} failed deliveries` : "Notifications"}><Icon name="bell" size={18}/>{failedDeliveries > 0 && <i className="badge-dot"/>}</Link>
          </div>
          {workspace.loading && <span className="progress" aria-hidden="true"/>}
        </header>
        <div className="page">
          {workspace.error && <div className="banner" role="alert"><Icon name="warning" size={16}/>Refresh failed: {workspace.error}. Data may be out of date.<button onClick={() => void workspace.actions.refresh()}>Retry</button></div>}
          {workspace.upgradeHint && <div className="banner" role="status"><Icon name="warning" size={16}/>The API runs an older build, so manifest freshness is unavailable. Rebuild with <code className="inline-code">docker compose up --build -d api worker</code>.</div>}
          {children}
        </div>
      </div>
      {notice && <div className={`toast is-${notice.kind}`} role="status"><span className="toast-mark"><Icon name={notice.kind === "error" ? "warning" : notice.kind === "info" ? "clock" : "check"} size={12}/></span><span>{notice.text}</span><button onClick={() => workspace.setNotice(null)} aria-label="Dismiss"><Icon name="close" size={14}/></button></div>}
    </div>
  );
}
