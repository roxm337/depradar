"use client";

import { Fragment, useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { dateTime, relativeTime } from "@/components/workspace/format";
import { Empty, PageHead, Segmented, Sheet, SkeletonRows, Switch } from "@/components/workspace/ui";
import type { DeliveryAttempt, NotificationPolicy } from "@/lib/api";

const hours = Array.from({ length: 24 }, (_, hour) => hour);
const zones = ["UTC", "Europe/Paris", "Europe/London", "Africa/Casablanca", "America/New_York", "America/Los_Angeles", "Asia/Dubai", "Asia/Singapore"];
const statusTone: Record<string, string> = { accepted: "dot-ok", failed: "dot-bad", cancelled: "", bundled: "", queued: "dot-warn dot-live", sending: "dot-warn dot-live", digest_pending: "dot-warn" };
const pad = (hour: number) => `${String(hour).padStart(2, "0")}:00`;

export default function NotificationsPage() {
  const workspace = useWorkspace();
  const { connectors, deliveries, policy, now, ready, actions } = workspace;
  const [attempts, setAttempts] = useState<Record<string, DeliveryAttempt[]>>({});
  const [limit, setLimit] = useState(25);
  async function toggleAttempts(id: string) {
    if (attempts[id]) { setAttempts((current) => { const next = { ...current }; delete next[id]; return next; }); return; }
    try { const rows = await actions.loadAttempts(id); setAttempts((current) => ({ ...current, [id]: rows })); }
    catch { workspace.notify("error", "Could not load delivery attempts."); }
  }

  return (
    <>
      <PageHead eyebrow="Configure" title="Notifications" lede="Where alerts go, when they are sent, and what happened to each delivery. Provider acceptance is recorded; inbox delivery cannot be confirmed."/>
      <div className="notif-grid">
        <Sheet title="Channels" meta="Verified destinations only">
          {(["email", "telegram"] as const).map((channel) => {
            const connector = connectors.find((item) => item.id === channel);
            const verified = Boolean(connector?.verified_at);
            const destination = channel === "email" ? String(connector?.config.recipient ?? "") : "Private chat";
            return (
              <div className="channel" key={channel}>
                <span className="channel-mark"><Icon name={channel === "email" ? "mail" : "send"} size={18}/></span>
                <div className="channel-copy">
                  <b>{channel === "email" ? "Email" : "Telegram"}<span className={`tag ${verified ? (connector?.enabled ? "tag-ok" : "tag-warn") : ""}`}>{verified ? (connector?.enabled ? "Active" : "Paused") : "Not connected"}</span></b>
                  <small>{verified ? `${destination} · verified ${relativeTime(now, connector?.verified_at)}` : connector ? (channel === "email" ? `Verification pending${destination ? ` for ${destination}` : ""} · check the delivery log` : "Pairing not finished") : "Connect a destination to receive alerts"}</small>
                </div>
                <div className="channel-actions">
                  {verified && <button className="btn btn-secondary btn-sm" onClick={() => void actions.connectorAction(channel, "test")}>Send test</button>}
                  {verified && <button className="btn btn-ghost btn-sm" onClick={() => void actions.connectorAction(channel, connector?.enabled ? "disable" : "enable")}>{connector?.enabled ? "Pause" : "Resume"}</button>}
                  <button className={`btn btn-sm ${verified ? "btn-ghost" : "btn-primary"}`} onClick={() => workspace.setModal({ kind: "connector", channel })}>{verified ? "Change" : "Connect"}</button>
                </div>
              </div>
            );
          })}
          <div className="sheet-foot"><Icon name="lock" size={14}/>SMTP passwords and bot tokens stay in the server environment and never reach this page.</div>
        </Sheet>
        <PolicyForm key={JSON.stringify(policy)} policy={policy} onSave={actions.savePolicy}/>
      </div>
      <Sheet title="Delivery log" meta={`${deliveries.length} recorded`}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Message</th><th className="col-optional">Channel</th><th>Status</th><th className="col-optional">Attempts</th><th className="col-optional">Created</th><th aria-label="Actions"/></tr></thead>
            <tbody>
              {!ready ? <SkeletonRows rows={4} columns={6}/> : deliveries.slice(0, limit).map((delivery) => (
                <Fragment key={delivery.id}>
                  <tr>
                    <td><div className="cell-main"><b>{delivery.kind.replaceAll("_", " ")}</b><small>{delivery.connector_id}{delivery.last_error ? ` · ${delivery.last_error.replaceAll("_", " ")}` : ""}</small></div></td>
                    <td className="col-optional muted">{delivery.connector_id}</td>
                    <td><span className="status"><i className={`dot ${statusTone[delivery.status] ?? ""}`}/>{delivery.status === "accepted" ? "Accepted" : delivery.status.replaceAll("_", " ")}</span></td>
                    <td className="col-optional mono">{delivery.attempts}</td>
                    <td className="col-optional muted">{dateTime(delivery.created_at)}</td>
                    <td className="right"><span className="row-actions">{delivery.attempts > 0 && <button className="btn btn-ghost btn-sm" onClick={() => void toggleAttempts(delivery.id)}>{attempts[delivery.id] ? "Hide" : "Attempts"}</button>}{delivery.status === "failed" && <button className="btn btn-secondary btn-sm" onClick={() => void actions.retryDelivery(delivery)}>Retry</button>}</span></td>
                  </tr>
                  {attempts[delivery.id] && <tr><td colSpan={6}><div className="attempts">{attempts[delivery.id].map((attempt) => <div className="attempt" key={attempt.id}><i className={`dot ${attempt.status === "accepted" ? "dot-ok" : attempt.status === "failed" ? "dot-bad" : "dot-warn"}`}/><b>Attempt {attempt.attempt_number}</b>{attempt.status}<span>{dateTime(attempt.started_at)}</span>{attempt.error_code && <span className="mono">{attempt.error_code}</span>}{attempt.provider_id && <span className="mono">provider {attempt.provider_id}</span>}</div>)}</div></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
          {ready && !deliveries.length && <Empty title="No deliveries yet" text="Verification messages, alerts, digests, and tests appear here with every provider attempt."/>}
        </div>
        {deliveries.length > limit && <div className="sheet-foot"><span>Showing {limit} of {deliveries.length}</span><button className="btn btn-secondary btn-sm" onClick={() => setLimit(limit + 25)}>Show more</button></div>}
      </Sheet>
    </>
  );
}

function PolicyForm({ policy, onSave }: { policy: NotificationPolicy; onSave: (value: NotificationPolicy) => Promise<boolean> }) {
  const [draft, setDraft] = useState(policy);
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(policy);
  const quiet = draft.quiet_hours_start !== null;
  return (
    <Sheet title="Alert policy" meta="Applies to every project unless overridden">
      <form className="sheet-body form-grid" onSubmit={(event) => { event.preventDefault(); setBusy(true); void onSave(draft).finally(() => setBusy(false)); }}>
        <div className="field"><span className="field-label">Send immediately from</span><Segmented label="Immediate threshold" value={draft.immediate_min_severity} onChange={(value) => setDraft({ ...draft, immediate_min_severity: value })} options={[{ value: "critical", label: "Critical" }, { value: "high", label: "High" }, { value: "medium", label: "Medium" }, { value: "low", label: "Low" }]}/><span className="field-hint">Lower severities wait for the daily digest. Expired or revoked risk acceptances always alert.</span></div>
        <div className="form-row">
          <label className="field"><span className="field-label">Daily digest at</span><select className="select" value={draft.digest_hour} onChange={(event) => setDraft({ ...draft, digest_hour: Number(event.target.value) })}>{hours.map((hour) => <option key={hour} value={hour}>{pad(hour)}</option>)}</select></label>
          <label className="field"><span className="field-label">Timezone</span><input className="input" list="timezones" value={draft.timezone} onChange={(event) => setDraft({ ...draft, timezone: event.target.value })}/><datalist id="timezones">{zones.map((zone) => <option key={zone} value={zone}/>)}</datalist></label>
        </div>
        <div className="toggle-row"><div><b>Quiet hours</b><small>Hold immediate alerts overnight and deliver them when the window ends.</small></div><Switch checked={quiet} label="Quiet hours" onChange={(enabled) => setDraft({ ...draft, quiet_hours_start: enabled ? 22 : null, quiet_hours_end: enabled ? 7 : null })}/></div>
        {quiet && <div className="form-row">
          <label className="field"><span className="field-label">From</span><select className="select" value={draft.quiet_hours_start ?? 22} onChange={(event) => setDraft({ ...draft, quiet_hours_start: Number(event.target.value) })}>{hours.map((hour) => <option key={hour} value={hour}>{pad(hour)}</option>)}</select></label>
          <label className="field"><span className="field-label">Until</span><select className="select" value={draft.quiet_hours_end ?? 7} onChange={(event) => setDraft({ ...draft, quiet_hours_end: Number(event.target.value) })}>{hours.map((hour) => <option key={hour} value={hour}>{pad(hour)}</option>)}</select></label>
        </div>}
        <div className="toggle-row"><div><b>Include project and package names</b><small>Off keeps external messages generic; details stay in DepRadar.</small></div><Switch checked={draft.include_details} label="Include details" onChange={(include_details) => setDraft({ ...draft, include_details })}/></div>
        <div className="page-actions"><button className="btn btn-primary" disabled={!dirty || busy}>{busy && <span className="spinner"/>}Save policy</button>{dirty && <button type="button" className="btn btn-ghost" onClick={() => setDraft(policy)}>Discard changes</button>}</div>
      </form>
    </Sheet>
  );
}
