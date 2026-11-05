"use client";

import type { ReactNode } from "react";
import { createPortal } from "react-dom";

/**
 * Renders overlays on <body>. A dialog opened inside an animated or transformed container (such
 * as a settings panel) would otherwise be positioned and clipped by that container.
 */
export function Portal({ children }: { children: ReactNode }) {
  return typeof document === "undefined" ? null : createPortal(children, document.body);
}
