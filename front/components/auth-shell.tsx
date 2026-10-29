import type { ReactNode } from "react";
import { Icon } from "@/components/icon";
import { Radar } from "@/components/radar";

const points = ["Isolated OSV scans with CISA KEV and EPSS context", "Pull request gates with SARIF, JUnit, and Markdown reports", "Self-hosted: inventories and credentials stay on your server"];

export function Brand() {
  return <div className="rail-brand"><span className="brand-mark"><span className="brand-glyph"/></span><span>dep<span>radar</span></span></div>;
}

export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <main className="auth-shell">
      <aside className="auth-aside">
        <Brand/>
        <div className="auth-pitch">
          <span className="eyebrow">Dependency security</span>
          <h1>See which client projects are exposed, and why.</h1>
          <p>DepRadar watches the lockfiles of every project you maintain, gates pull requests in CI/CD, and alerts you by email and Telegram.</p>
          <ul className="auth-points">{points.map((point) => <li key={point}><Icon name="check" size={15}/>{point}</li>)}</ul>
        </div>
        <Radar className="auth-radar" blips={[{ id: "a1", severity: "critical" }, { id: "b7", severity: "high" }, { id: "c3", severity: "medium" }, { id: "d9", severity: "low" }, { id: "e2", severity: "high" }]}/>
        <span className="auth-foot">OSV · CISA KEV · FIRST EPSS</span>
      </aside>
      <section className="auth-main"><div className="auth-card">{children}</div></section>
    </main>
  );
}

export function ApiUnavailable({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <>
      <div className="auth-heading"><span className="auth-icon warning"><Icon name="server" size={19}/></span><h2>Can’t reach DepRadar</h2><p>{detail || "The web app could not reach the DepRadar API. Start the backend, then try again."}</p></div>
      <code className="code">docker compose up -d</code>
      <p className="auth-help"><Icon name="terminal" size={14}/><span>If the API runs on another port, start the web app with <code>DEPRADAR_API_URL</code> pointing to it.</span></p>
      <button className="btn btn-primary auth-submit" onClick={onRetry}><Icon name="refresh" size={16}/>Try again</button>
    </>
  );
}

export function Checking({ label }: { label: string }) {
  return <div className="auth-status" role="status"><span className="spinner"/>{label}</div>;
}
