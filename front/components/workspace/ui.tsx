"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Icon } from "@/components/icon";
import { SEVERITIES, severityOf, type Severity } from "@/components/workspace/format";

export function PageHead({ eyebrow, title, lede, actions }: { eyebrow: string; title: string; lede?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div><span className="eyebrow">{eyebrow}</span><h1 className="page-title">{title}</h1>{lede && <p className="lede">{lede}</p>}</div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Sheet({ title, meta, actions, foot, children, className = "" }: { title?: ReactNode; meta?: ReactNode; actions?: ReactNode; foot?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`sheet ${className}`}>
      {title && <div className="sheet-head"><h2>{title}</h2>{meta && <span className="meta">{meta}</span>}{actions && <div className="actions">{actions}</div>}</div>}
      {children}
      {foot && <div className="sheet-foot">{foot}</div>}
    </section>
  );
}

export function Sev({ value }: { value: string }) {
  const severity = severityOf(value);
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}

export function Pkg({ name, version }: { name: string; version: string }) {
  return <span className="pkg">{name}<span>@{version}</span></span>;
}

export function StackBar({ counts, total }: { counts: Record<Severity, number>; total: number }) {
  return <span className="stack" role="img" aria-label={SEVERITIES.map((level) => `${counts[level]} ${level}`).join(", ")}>{total ? SEVERITIES.filter((level) => counts[level]).map((level) => <i key={level} className={`bar-${level}`} style={{ width: `${(counts[level] / total) * 100}%` }}/>) : null}</span>;
}

export function Empty({ title, text, action }: { title: string; text: string; action?: ReactNode }) {
  return <div className="empty"><span className="empty-glyph" aria-hidden="true"/><b>{title}</b><p>{text}</p>{action}</div>;
}

export function SkeletonRows({ rows = 5, columns }: { rows?: number; columns: number }) {
  return <>{Array.from({ length: rows }, (_, row) => <tr key={row} className="table-skeleton">{Array.from({ length: columns }, (_, column) => <td key={column}><span className="skeleton" style={{ width: `${40 + ((row * 7 + column * 13) % 50)}%` }}/></td>)}</tr>)}</>;
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string; count?: number }[]; onChange: (value: T) => void; label: string }) {
  return <div className="seg" role="group" aria-label={label}>{options.map((option) => <button key={option.value} type="button" aria-pressed={value === option.value} onClick={() => onChange(option.value)}>{option.label}{option.count !== undefined && <small>{option.count}</small>}</button>)}</div>;
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (checked: boolean) => void; label: string; disabled?: boolean }) {
  return <button type="button" role="switch" className="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={(event) => { event.stopPropagation(); onChange(!checked); }}/>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return <button type="button" className="btn btn-secondary btn-sm" onClick={() => void navigator.clipboard.writeText(value).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1600); })}><Icon name={copied ? "check" : "copy"} size={14}/>{copied ? "Copied" : label}</button>;
}

function useOverlay(onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    ref.current?.focus();
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = overflow; previous?.focus?.(); };
  }, [onClose]);
  return ref;
}

export function Drawer({ label, onClose, children }: { label: string; onClose: () => void; children: ReactNode }) {
  const ref = useOverlay(onClose);
  return <><div className="overlay" onClick={onClose}/><aside ref={ref} className="drawer" role="dialog" aria-modal="true" aria-label={label} tabIndex={-1}>{children}</aside></>;
}

export function Modal({ title, description, onClose, steps, children }: { title: string; description?: string; onClose: () => void; steps?: [number, number]; children: ReactNode }) {
  const ref = useOverlay(onClose);
  return (
    <div className="modal-layer" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section ref={ref} className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" tabIndex={-1}>
        {steps && <div className="steps" aria-label={`Step ${steps[0]} of ${steps[1]}`}>{Array.from({ length: steps[1] }, (_, index) => <span key={index} className={index < steps[0] ? "is-done" : ""}/>)}</div>}
        <div className="modal-head"><div><h2 id="modal-title">{title}</h2>{description && <p>{description}</p>}</div><button className="icon-btn" onClick={onClose} aria-label="Close dialog"><Icon name="close"/></button></div>
        {children}
      </section>
    </div>
  );
}
