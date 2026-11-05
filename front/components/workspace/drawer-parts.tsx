"use client";

import { useEffect, useRef, useState } from "react";
import { Icon } from "@/components/icon";
import { dateTime, relativeTime } from "@/components/workspace/format";
import type { TimelineEvent } from "@/components/workspace/drawer-format";

/** Copies text. `navigator.clipboard` only exists on HTTPS and localhost, so fall back to a hidden field. */
export async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard) { await navigator.clipboard.writeText(value); return true; }
  } catch { /* fall through to the legacy path */ }
  const field = document.createElement("textarea");
  field.value = value;
  field.setAttribute("readonly", "");
  field.style.cssText = "position:fixed;top:-100px;opacity:0";
  document.body.appendChild(field);
  field.select();
  try { return document.execCommand("copy"); } finally { field.remove(); }
}

export function VersionChip({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <button type="button" className={`version-chip ${copied ? "is-copied" : ""}`} aria-label={`Copy ${value}`} onClick={() => void copyText(value).then((done) => { if (!done) return; setCopied(true); window.clearTimeout(timer.current); timer.current = window.setTimeout(() => setCopied(false), 1600); })}>
      {value}<Icon name={copied ? "check" : "copy"} size={13}/>{copied && <span className="sr-only">Copied</span>}
    </button>
  );
}

const toneDot = { ok: "dot-ok", warn: "dot-warn", neutral: "" } as const;

export function DecisionTimeline({ events, now }: { events: TimelineEvent[]; now: number }) {
  return (
    <div className="timeline">
      {events.map((event) => (
        <div className="timeline-item" key={event.id}>
          <span className={`dot ${toneDot[event.tone]}`}/>
          <div><b>{event.title}</b>{event.note && <p className="timeline-note">{event.note}</p>}{event.expiresAt && <small>Expires {dateTime(event.expiresAt)}</small>}</div>
          <time dateTime={event.at} title={dateTime(event.at)}>{relativeTime(now, event.at)}</time>
        </div>
      ))}
    </div>
  );
}
