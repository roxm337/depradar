"use client";

import { Fragment, useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { channelLabel, dateTime, deliveryKindLabel, deliveryStatusLabel, projectName, relativeTime } from "@/components/workspace/format";
import { Pagination } from "@/components/workspace/pagination";
import { Empty, PageHead, Segmented, Sheet, SkeletonRows, Switch } from "@/components/workspace/ui";
import type { Delivery, DeliveryAttempt, NotificationPolicy } from "@/lib/api";

const hours = Array.from({ length: 24 }, (_, hour) => hour);
const zones = ["UTC", "Europe/Paris", "Europe/London", "Africa/Casablanca", "America/New_York", "America/Los_Angeles", "Asia/Dubai", "Asia/Singapore"];
const statusTone: Record<string, string> = { accepted: "dot-ok", failed: "dot-bad", cancelled: "", bundled: "", queued: "dot-warn dot-live", sending: "dot-warn dot-live", digest_pending: "dot-warn" };
const pad = (hour: number) => `${String(hour).padStart(2, "0")}:00`;
type LogFilter = "all" | "failed" | "pending";
const PENDING = new Set(["queued", "sending", "digest_pending"]);
const matches = (filter: LogFilter, delivery: Delivery) => filter === "all" || (filter === "failed" ? delivery.status === "failed" : PENDING.has(delivery.status));

export default function NotificationsPage() {
  const workspace = useWorkspace();
  const { connectors, deliveries, policy, projects, now, ready, actions } = workspace;
  const [attempts, setAttempts] = useState<Record<string, DeliveryAttempt[]>>({});
  const [filter, setFilter] = useState<LogFilter>("all");
  const [page, setPage] = useState({ filter: "all" as LogFilter, value: 1 });
  const [pageSize, setPageSize] = useState(25);
  const current = page.filter === filter ? page.value : 1;
  const shown = deliveries.filter((delivery) => matches(filter, delivery));
  const rows = shown.slice((current - 1) * pageSize, current * pageSize);
  const failed = deliveries.filter((delivery) => delivery.status === "failed").length;
  const pending = deliveries.filter((delivery) => PENDING.has(delivery.status)).length;
  async function toggleAttempts(id: string) {
    if (attempts[id]) { setAttempts((current) => { const next = { ...current }; delete next[id]; return next; }); return; }
    try { const rows = await actions.loadAttempts(id); setAttempts((current) => ({ ...current, [id]: rows })); }
    catch { workspace.notify("error", "Could not load delivery attempts."); }
  }

  return (
    <>
      <PageHead title="Notifications" lede="Where alerts go, when they are sent, and what happened to each one. DepRadar records when your mail server or Telegram accepts a message, but cannot confirm it reached the inbox."/>
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
                  {verified ? <><small title={destination}>{destination}</small><small>Verified {relativeTime(now, connector?.verified_at)}</small></> : <small>{connector ? (channel === "email" ? `Verification pending${destination ? ` for ${destination}` : ""} · check the delivery log` : "Pairing not finished") : "Connect a destination to receive alerts"}</small>}
                </div>
                <div className="channel-actions">
                  {verified && <button className="btn btn-secondary btn-sm" onClick={() => void actions.connectorAction(channel, "test")}>Send test</button>}
                  {verified && <button className="btn btn-ghost btn-sm" onClick={() => void actions.connectorAction(channel, connector?.enabled ? "disable" : "enable")}>{connector?.enabled ? "Pause" : "Resume"}</button>}
                  <button className={`btn btn-sm ${verified ? "btn-ghost" : "btn-primary"}`} onClick={() => workspace.setModal({ kind: "connector", channel })}>{verified ? "Change" : "Connect"}</button>
                </div>
              </div>
            );
          })}
          <div className="sheet-foot"><Icon name="lock" size={14}/>Mail server passwords and bot tokens are set on the server and never shown on this page.</div>
        </Sheet>
        <PolicyForm key={JSON.stringify(policy)} policy={policy} onSave={actions.savePolicy}/>
      </div>
      <Sheet title="Delivery log" meta={`${deliveries.length} recorded`} actions={<Segmented label="Show deliveries" value={filter} onChange={setFilter} options={[{ value: "all", label: "All", count: deliveries.length }, { value: "failed", label: "Failed", count: failed }, { value: "pending", label: "Pending", count: pending }]}/>}>
        <div className="table-wrap">
          <table className="table delivery-table">
            <thead><tr><th>Message</th><th className="col-optional">Channel</th><th>Status</th><th className="col-optional">Attempts</th><th className="col-optional">Created</th><th aria-label="Actions"/></tr></thead>
            <tbody>
              {!ready ? <SkeletonRows rows={4} columns={6}/> : rows.map((delivery) => (
                <Fragment key={delivery.id}>
                  <tr>
                    <td><div className="cell-main"><b>{deliveryKindLabel(delivery.kind)}</b><small>{delivery.project_id ? projectName(projects, delivery.project_id) : delivery.kind === "digest" ? "Every project" : "Workspace"}</small>{delivery.last_error && <small className="delivery-error mono" title="Provider error code">{delivery.last_error}</small>}</div></td>
                    <td className="col-optional"><span className="delivery-channel"><Icon name={delivery.connector_id === "email" ? "mail" : "send"} size={14}/>{channelLabel(delivery.connector_id)}</span></td>
                    <td><span className="status"><i className={`dot ${statusTone[delivery.status] ?? ""}`}/>{deliveryStatusLabel(delivery.status)}</span></td>
                    <td className="col-optional">{delivery.attempts > 0 ? <button className="link delivery-attempts" aria-expanded={Boolean(attempts[delivery.id])} onClick={() => void toggleAttempts(delivery.id)}>{delivery.attempts} {delivery.attempts === 1 ? "attempt" : "attempts"}<Icon name={attempts[delivery.id] ? "chevron-up" : "chevron-down"} size={13}/></button> : <span className="muted">None yet</span>}</td>
                    <td className="col-optional muted nowrap"><time dateTime={delivery.created_at} title={dateTime(delivery.created_at)}>{relativeTime(now, delivery.created_at)}</time></td>
                    <td className="right">{delivery.status === "failed" && <button className="btn btn-secondary btn-sm" onClick={() => void actions.retryDelivery(delivery)}><Icon name="refresh" size={13}/>Retry</button>}</td>
                  </tr>
                  {attempts[delivery.id] && <tr className="attempts-row"><td colSpan={6}><div className="attempts">{!attempts[delivery.id].length && <span className="muted">No attempt details were recorded for this delivery.</span>}{attempts[delivery.id].map((attempt) => <div className="attempt" key={attempt.id}><i className={`dot ${attempt.status === "accepted" ? "dot-ok" : attempt.status === "failed" ? "dot-bad" : "dot-warn"}`}/><b>Attempt {attempt.attempt_number}</b>{deliveryStatusLabel(attempt.status)}<span>{dateTime(attempt.started_at)}</span>{attempt.error_code && <span className="mono">{attempt.error_code}</span>}{attempt.provider_id && <span className="mono">provider {attempt.provider_id}</span>}</div>)}</div></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
          {ready && !deliveries.length && <Empty icon="bell" title="No deliveries yet" text="Verification messages, alerts, digests, and test messages appear here, with every attempt to send them."/>}
          {ready && deliveries.length > 0 && !shown.length && <Empty icon="check-circle" title={filter === "failed" ? "No failed deliveries" : "Nothing waiting to send"} text={filter === "failed" ? "Every recorded message was accepted by your mail server or Telegram, or is still being retried." : "Queued alerts and digests appear here until your mail server or Telegram accepts them."}/>}
        </div>
        {ready && shown.length > 0 && <Pagination total={shown.length} page={current} pageSize={pageSize} sizes={[25, 50, 100]} noun="deliveries" onPage={(value) => setPage({ filter, value })} onPageSize={(size) => { setPageSize(size); setPage({ filter, value: 1 }); }}/>}
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
    <Sheet title="Alert settings" meta="Apply to every project unless the project sets its own level">
      <form className="sheet-body form-grid" onSubmit={(event) => { event.preventDefault(); setBusy(true); void onSave(draft).finally(() => setBusy(false)); }}>
        <div className="field"><span className="field-label">Send immediately for this severity and above</span><Segmented label="Immediate threshold" value={draft.immediate_min_severity} onChange={(value) => setDraft({ ...draft, immediate_min_severity: value })} options={[{ value: "critical", label: "Critical" }, { value: "high", label: "High" }, { value: "medium", label: "Medium" }, { value: "low", label: "Low" }]}/><span className="field-hint">Lower severities wait for the daily digest, one summary message a day. An expired or revoked risk acceptance always sends an alert.</span></div>
        <div className="form-row">
          <label className="field"><span className="field-label">Daily digest at</span><select className="select" value={draft.digest_hour} onChange={(event) => setDraft({ ...draft, digest_hour: Number(event.target.value) })}>{hours.map((hour) => <option key={hour} value={hour}>{pad(hour)}</option>)}</select></label>
          <label className="field"><span className="field-label">Timezone</span><input className="input" list="timezones" value={draft.timezone} onChange={(event) => setDraft({ ...draft, timezone: event.target.value })}/><datalist id="timezones">{zones.map((zone) => <option key={zone} value={zone}/>)}</datalist></label>
        </div>
        <div className="toggle-row"><div><b>Quiet hours</b><small>Hold immediate alerts during these hours and send them when the quiet hours end.</small></div><Switch checked={quiet} label="Quiet hours" onChange={(enabled) => setDraft({ ...draft, quiet_hours_start: enabled ? 22 : null, quiet_hours_end: enabled ? 7 : null })}/></div>
        {quiet && <div className="form-row">
          <label className="field"><span className="field-label">From</span><select className="select" value={draft.quiet_hours_start ?? 22} onChange={(event) => setDraft({ ...draft, quiet_hours_start: Number(event.target.value) })}>{hours.map((hour) => <option key={hour} value={hour}>{pad(hour)}</option>)}</select></label>
          <label className="field"><span className="field-label">Until</span><select className="select" value={draft.quiet_hours_end ?? 7} onChange={(event) => setDraft({ ...draft, quiet_hours_end: Number(event.target.value) })}>{hours.map((hour) => <option key={hour} value={hour}>{pad(hour)}</option>)}</select></label>
        </div>}
        <div className="toggle-row"><div><b>Include project and package names</b><small>When off, alerts and digests leave out project and package names; open DepRadar to see them.</small></div><Switch checked={draft.include_details} label="Include details" onChange={(include_details) => setDraft({ ...draft, include_details })}/></div>
        <div className="page-actions"><button className="btn btn-primary" disabled={!dirty || busy}>{busy && <span className="spinner"/>}Save settings</button>{dirty && <button type="button" className="btn btn-ghost" onClick={() => setDraft(policy)}>Discard changes</button>}</div>
      </form>
    </Sheet>
  );
}
