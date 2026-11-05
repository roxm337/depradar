"use client";

import { useCallback, useState } from "react";

/**
 * State that survives reloads in localStorage. The workspace only renders after the session is
 * confirmed on the client, so reading storage in the initializer cannot cause a hydration mismatch.
 * Pass module-level `parse` and `serialize` functions so the setter stays stable.
 */
export function useStored<T>(key: string, parse: (raw: string | null) => T, serialize: (value: T) => string): [T, (value: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try { return parse(typeof window === "undefined" ? null : window.localStorage.getItem(key)); } catch { return parse(null); }
  });
  const save = useCallback((next: T) => {
    setValue(next);
    try { window.localStorage.setItem(key, serialize(next)); } catch { /* private mode: the choice lasts for this page only */ }
  }, [key, serialize]);
  return [value, save];
}
