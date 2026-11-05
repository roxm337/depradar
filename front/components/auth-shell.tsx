import type { ReactNode } from "react";
import { Icon } from "@/components/icon";

export function Brand() {
  return (
    <div className="brand">
      <svg className="brand-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="m12 12 6.4-6.4"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg>
      <span className="brand-word">dep<span>radar</span></span>
    </div>
  );
}

export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <main className="auth-shell">
      <Brand/>
      <div className="auth-card">{children}</div>
      <p className="auth-foot">Self-hosted. Your inventories and credentials stay on your server.</p>
    </main>
  );
}

export function ApiUnavailable({ detail, onRetry, signedIn = false }: { detail: string; onRetry: () => void; signedIn?: boolean }) {
  if (signedIn) {
    return (
      <>
        <div className="auth-heading"><span className="auth-icon warning"><Icon name="server" size={19}/></span><h2>Workspace data didn’t load</h2><p>You are signed in, but loading projects and findings failed{detail ? `: ${detail}` : "."} Nothing is shown rather than an incomplete picture.</p></div>
        <button className="btn btn-primary auth-submit" onClick={onRetry}><Icon name="refresh" size={16}/>Try again</button>
      </>
    );
  }
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
