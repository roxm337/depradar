"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { Modal } from "@/components/workspace/ui";

const FIRST_FIELD = "[data-autofocus], input:not([type=hidden]):not([disabled]), textarea:not([disabled]), select:not([disabled])";

/**
 * Content wrapper for dialogs opened above a drawer or page.
 * - Escape closes only this dialog; without this the drawer underneath closes with it.
 * - Focus moves to the first field (or the element marked `data-autofocus`) after the Modal
 *   primitive has finished placing focus on its own container.
 */
export function DialogContent({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const frame = requestAnimationFrame(() => root.current?.querySelector<HTMLElement>(FIRST_FIELD)?.focus());
    return () => cancelAnimationFrame(frame);
  }, []);
  return <div ref={root} onKeyDown={(event) => { if (event.key === "Escape") { event.stopPropagation(); onClose(); } }}>{children}</div>;
}

/** A modal whose Escape and initial focus behave correctly when stacked above a drawer. */
export function Dialog({ title, description, onClose, steps, children }: { title: string; description?: string; onClose: () => void; steps?: [number, number]; children: ReactNode }) {
  return <Modal title={title} description={description} onClose={onClose} steps={steps}><DialogContent onClose={onClose}>{children}</DialogContent></Modal>;
}

/** Confirmation for a destructive action. Cancel has focus first, so Enter never confirms by accident. */
export function ConfirmDialog({ title, description, confirmLabel, busy = false, onConfirm, onClose, children }: { title: string; description?: string; confirmLabel: string; busy?: boolean; onConfirm: () => void; onClose: () => void; children: ReactNode }) {
  return (
    <Dialog title={title} description={description} onClose={onClose}>
      <div className="modal-body">{children}</div>
      <div className="modal-foot">
        <button type="button" className="btn btn-ghost" data-autofocus onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-danger" disabled={busy} onClick={onConfirm}>{busy && <span className="spinner"/>}{confirmLabel}</button>
      </div>
    </Dialog>
  );
}
