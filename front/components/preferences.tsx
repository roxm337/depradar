"use client";

import { useCallback, useEffect, useSyncExternalStore } from "react";

// Interface preferences live in localStorage and on <html data-*> attributes, which the root layout
// sets before first paint. Components read them through usePreference so every consumer stays in sync.
export type Theme = "light" | "dark" | "system";
export type Density = "comfortable" | "compact";
export type Navigation = "expanded" | "collapsed";

type Preferences = { theme: Theme; density: Density; nav: Navigation };
const KEYS: Record<keyof Preferences, string> = { theme: "depradar-theme", density: "depradar-density", nav: "depradar-nav" };
const DEFAULTS: Preferences = { theme: "system", density: "comfortable", nav: "expanded" };
const listeners = new Set<() => void>();

function read<K extends keyof Preferences>(name: K): Preferences[K] {
  try { return (localStorage.getItem(KEYS[name]) as Preferences[K] | null) ?? DEFAULTS[name]; } catch { return DEFAULTS[name]; }
}

function apply() {
  const root = document.documentElement;
  const theme = read("theme");
  root.dataset.theme = theme === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : theme;
  root.dataset.density = read("density");
  root.dataset.nav = read("nav");
}

export function setPreference<K extends keyof Preferences>(name: K, value: Preferences[K]) {
  try { localStorage.setItem(KEYS[name], value); } catch { /* private mode: the choice lasts for this page only */ }
  apply();
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => { listeners.delete(listener); window.removeEventListener("storage", listener); };
}

export function usePreference<K extends keyof Preferences>(name: K): [Preferences[K], (value: Preferences[K]) => void] {
  const value = useSyncExternalStore(subscribe, () => read(name), () => DEFAULTS[name]);
  const set = useCallback((next: Preferences[K]) => setPreference(name, next), [name]);
  return [value, set];
}

// Follow the operating system while the theme is "system".
export function useSystemThemeSync() {
  useEffect(() => {
    const query = matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => { if (read("theme") === "system") apply(); };
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);
}
