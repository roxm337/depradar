"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Icon } from "@/components/icon";
import { SEVERITIES, severityOf, type Severity } from "@/components/workspace/format";

export function PageHead({ eyebrow, title, lede, actions }: { eyebrow?: string; title: string; lede?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h1 className="page-title">{title}</h1>{lede && <p className="lede">{lede}</p>}</div>
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

export function Empty({ title, text, action, icon = "inbox" }: { title: string; text: string; action?: ReactNode; icon?: string }) {
  return <div className="empty"><span className="empty-glyph" aria-hidden="true"><Icon name={icon} size={20}/></span><b>{title}</b><p>{text}</p>{action}</div>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd>{children}</kbd>;
}

export function Checkbox({ checked, indeterminate = false, onChange, label }: { checked: boolean; indeterminate?: boolean; onChange: (checked: boolean) => void; label: string }) {
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (input.current) input.current.indeterminate = indeterminate && !checked; }, [indeterminate, checked]);
  return <span className="check"><input ref={input} type="checkbox" checked={checked} aria-label={label} onChange={(event) => onChange(event.target.checked)} onClick={(event) => event.stopPropagation()}/><i><Icon name={indeterminate && !checked ? "minus" : "check"} size={12}/></i></span>;
}

type MenuTrigger = { open: boolean; toggle: () => void; props: { "aria-haspopup": "menu"; "aria-expanded": boolean; onClick: () => void } };

/** A popover menu: Escape and outside clicks close it, arrow keys move between items. */
export function Menu({ trigger, children, label, align = "right", up = false }: { trigger: (state: MenuTrigger) => ReactNode; children: (close: () => void) => ReactNode; label: string; align?: "left" | "right"; up?: boolean }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const close = useCallback(() => setOpen(false), []);
  const toggle = useCallback(() => setOpen((value) => !value), []);
  useEffect(() => {
    if (!open) return;
    const onDown = (event: PointerEvent) => { if (!wrap.current?.contains(event.target as Node)) setOpen(false); };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      wrap.current?.querySelector<HTMLElement>("[aria-haspopup]")?.focus();
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    panel.current?.focus();
    return () => { document.removeEventListener("pointerdown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);
  const move = (direction: number) => {
    const items = [...(panel.current?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? [])];
    if (!items.length) return;
    const index = items.indexOf(document.activeElement as HTMLElement);
    items[(index + direction + items.length) % items.length].focus();
  };
  return (
    <div className="menu-wrap" ref={wrap}>
      {trigger({ open, toggle, props: { "aria-haspopup": "menu", "aria-expanded": open, onClick: toggle } })}
      {open && <div ref={panel} role="menu" aria-label={label} tabIndex={-1} className={`menu-panel ${align === "left" ? "is-left" : ""} ${up ? "is-up" : ""}`} onKeyDown={(event) => { if (event.key === "ArrowDown") { event.preventDefault(); move(1); } else if (event.key === "ArrowUp") { event.preventDefault(); move(-1); } }}>{children(close)}</div>}
    </div>
  );
}

export function MenuItem({ icon, children, end, onSelect, checked, danger = false }: { icon?: string; children: ReactNode; end?: ReactNode; onSelect: () => void; checked?: boolean; danger?: boolean }) {
  return <button type="button" role={checked === undefined ? "menuitem" : "menuitemradio"} aria-checked={checked} className={`menu-item ${danger ? "is-danger" : ""}`} onClick={onSelect}>{icon && <Icon name={icon} size={15}/>}{children}{(end || checked) && <span className="menu-end">{end ?? <Icon name="check" size={14}/>}</span>}</button>;
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

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Dialogs hold focus: Tab cycles inside, Escape closes, and focus returns to what opened them.
function useOverlay(onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  useEffect(() => { close.current = onClose; });
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    ref.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") { close.current(); return; }
      if (event.key !== "Tab" || !ref.current) return;
      const items = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((item) => item.offsetParent !== null);
      if (!items.length) return;
      const first = items[0], last = items[items.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = overflow; previous?.focus?.(); };
  }, []);
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
