"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiUnavailable, AuthShell, Checking } from "@/components/auth-shell";
import { Icon } from "@/components/icon";
import { api, ApiError, json } from "@/lib/api";

type Stage = "checking" | "offline" | "setup" | "login";
const reasons: Record<string, string> = { expired: "Your session ended. Sign in again to continue.", signed_out: "You have signed out." };

export default function LoginPage() {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>("checking");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [offlineDetail, setOfflineDetail] = useState("");
  const [busy, setBusy] = useState(false);
  const [reveal, setReveal] = useState(false);

  const check = useCallback(async () => {
    // Revisited routes keep their state, so clear any earlier in-flight sign-in.
    setStage("checking"); setError(""); setBusy(false); setReveal(false);
    try {
      const status = await api<{ initialized: boolean }>("auth/status");
      if (!status.initialized) { setStage("setup"); return; }
      await api("auth/me");
      router.replace("/");
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) { setStage("login"); return; }
      setOfflineDetail(failure instanceof ApiError ? failure.message : ""); setStage("offline");
    }
  }, [router]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams(window.location.search);
      setNotice(Object.entries(reasons).find(([key]) => params.has(key))?.[1] ?? "");
      void check();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [check]);

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget).get("password") ?? "");
    setBusy(true); setError(""); setNotice("");
    try { await api("auth/login", json("POST", { password })); router.replace("/"); }
    catch (failure) {
      setBusy(false);
      if (!(failure instanceof ApiError)) { setStage("offline"); return; }
      if (failure.status === 401) setError("That password is not correct.");
      else if (failure.status === 429) setError("Too many attempts. Wait 15 minutes, then try again.");
      else if (failure.status === 403) setError("The API rejected this site’s origin. Start the web app with DEPRADAR_ALLOWED_ORIGIN set to the API’s allowed origin.");
      else if (failure.status === 503) { setOfflineDetail(failure.message); setStage("offline"); }
      else setError(failure.message);
    }
  }

  return (
    <AuthShell>
      {stage === "checking" && <Checking label="Checking your session…"/>}
      {stage === "offline" && <ApiUnavailable detail={offlineDetail} onRetry={() => void check()}/>}
      {stage === "setup" && (
        <>
          <div className="auth-heading"><span className="auth-icon"><Icon name="key" size={19}/></span><h2>Finish setting up DepRadar</h2><p>No owner account exists yet. Create one on the server, then check again.</p></div>
          <code className="code">docker compose exec api depradar setup-owner</code>
          <p className="auth-help"><Icon name="shield" size={14}/><span>The command asks for a password of 12–128 characters. There is no public registration.</span></p>
          <button className="btn btn-primary auth-submit" onClick={() => void check()}>Check again<Icon name="arrow" size={16}/></button>
        </>
      )}
      {stage === "login" && (
        <>
          <div className="auth-heading"><span className="auth-icon"><Icon name="lock" size={19}/></span><h2>Sign in</h2><p>Use the owner password for this DepRadar installation.</p></div>
          {notice && <div className="auth-message" role="status"><Icon name="check" size={16}/>{notice}</div>}
          {error && <div className="auth-message auth-error" role="alert"><Icon name="warning" size={16}/>{error}</div>}
          <form onSubmit={signIn}>
            <input className="sr-only" name="username" autoComplete="username" value="owner" readOnly tabIndex={-1} aria-hidden="true"/>
            <label className="field">
              <span className="field-label">Password</span>
              <span className="password-field">
                <input className="input" name="password" type={reveal ? "text" : "password"} autoComplete="current-password" minLength={12} maxLength={128} required autoFocus placeholder="Enter your password" aria-invalid={Boolean(error)}/>
                <button type="button" className="password-toggle" onClick={() => setReveal(!reveal)} aria-label={reveal ? "Hide password" : "Show password"} aria-pressed={reveal}><Icon name={reveal ? "eye-off" : "eye"} size={17}/></button>
              </span>
            </label>
            <button className="btn btn-primary auth-submit" type="submit" disabled={busy}>{busy ? <><span className="spinner"/>Signing in…</> : <>Sign in<Icon name="arrow" size={16}/></>}</button>
          </form>
          <p className="auth-help"><Icon name="shield" size={14}/><span>Forgot it? On the server, run <code>docker compose exec api depradar reset-password</code>. Every session is signed out.</span></p>
        </>
      )}
    </AuthShell>
  );
}
