"use client";

import { useEffect, useRef, useState } from "react";
import { SEVERITIES, type Severity } from "@/components/workspace/format";
import { axis, type AgeBucket, type Counts, type SeriesPoint } from "@/components/workspace/trend";

const HEIGHT = 232;
const MARGIN = { top: 10, right: 12, bottom: 26, left: 34 };
const dayFormat = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" });
const longFormat = new Intl.DateTimeFormat("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric" });
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.round(entry.contentRect.width)));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

const summary = (counts: Counts) => SEVERITIES.filter((level) => counts[level]).map((level) => `${counts[level]} ${level}`).join(", ") || "none";

/**
 * Open findings over time, stacked by severity, most severe at the bottom. Hover or use the arrow
 * keys to read any day; the legend always shows the counts for the day being read.
 */
export function TrendChart({ series }: { series: SeriesPoint[] }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const last = series.length - 1;
  const index = hover ?? last;
  const point = series[index];
  const peak = Math.max(0, ...series.map((entry) => entry.total));
  const { max, step } = axis(peak);
  const plotWidth = Math.max(width - MARGIN.left - MARGIN.right, 0);
  const plotHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const x = (position: number) => MARGIN.left + (last <= 0 ? 0 : (position / last) * plotWidth);
  const y = (value: number) => MARGIN.top + plotHeight - (value / max) * plotHeight;

  const areas = SEVERITIES.map((level, order) => {
    const below = SEVERITIES.slice(0, order);
    const top = series.map((entry) => below.reduce((sum, name) => sum + entry.counts[name], 0) + entry.counts[level]);
    const bottom = series.map((entry) => below.reduce((sum, name) => sum + entry.counts[name], 0));
    const upper = top.map((value, position) => `${position ? "L" : "M"}${x(position).toFixed(1)},${y(value).toFixed(1)}`).join("");
    const lower = bottom.map((value, position) => `L${x(position).toFixed(1)},${y(value).toFixed(1)}`).reverse().join("");
    return { level, path: `${upper}${lower}Z`, used: top.some((value, position) => value > bottom[position]) };
  });
  const ticks = Array.from({ length: Math.floor(max / step) + 1 }, (_, position) => position * step);
  const labels = width >= 560 ? 6 : 4;
  const labelAt = Array.from({ length: labels }, (_, position) => Math.round((position / (labels - 1)) * last));

  function move(clientX: number, box: DOMRect) {
    if (plotWidth <= 0 || last <= 0) return;
    const ratio = (clientX - box.left - MARGIN.left) / plotWidth;
    setHover(Math.min(last, Math.max(0, Math.round(ratio * last))));
  }

  if (!series.length || peak === 0) return <div className="chart-empty">No findings were open in this period.</div>;
  const tipOnLeft = width > 0 && x(index) > width * 0.6;

  return (
    <div className="chart" ref={ref}>
      <div
        className="chart-plot" style={{ height: HEIGHT }} tabIndex={0} role="group" aria-label={`Open findings over the last ${plural(series.length, "day")}. Use the left and right arrow keys to read a day.`}
        onPointerMove={(event) => move(event.clientX, event.currentTarget.getBoundingClientRect())} onPointerLeave={() => setHover(null)}
        onFocus={() => setHover((current) => current ?? last)} onBlur={() => setHover(null)}
        onKeyDown={(event) => {
          if (event.key === "ArrowLeft") { event.preventDefault(); setHover(Math.max(0, index - 1)); }
          else if (event.key === "ArrowRight") { event.preventDefault(); setHover(Math.min(last, index + 1)); }
          else if (event.key === "Home") { event.preventDefault(); setHover(0); }
          else if (event.key === "End") { event.preventDefault(); setHover(last); }
          else if (event.key === "Escape") setHover(null);
        }}
      >
        {width > 0 && (
          <svg width={width} height={HEIGHT} aria-hidden="true">
            {ticks.map((tick) => (
              <g key={tick}>
                <line className="chart-grid" x1={MARGIN.left} x2={width - MARGIN.right} y1={y(tick)} y2={y(tick)}/>
                <text className="chart-label" x={MARGIN.left - 8} y={y(tick)} textAnchor="end" dominantBaseline="middle">{tick}</text>
              </g>
            ))}
            {areas.filter((area) => area.used).map((area) => <path key={area.level} className={`area area-${area.level}`} d={area.path}/>)}
            {labelAt.map((position, order) => (
              <text key={position} className="chart-label" x={x(position)} y={HEIGHT - 6} textAnchor={order === 0 ? "start" : order === labelAt.length - 1 ? "end" : "middle"}>{dayFormat.format(series[position].at)}</text>
            ))}
            {hover !== null && <line className="chart-cursor" x1={x(hover)} x2={x(hover)} y1={MARGIN.top} y2={MARGIN.top + plotHeight}/>}
          </svg>
        )}
        {hover !== null && width > 0 && (
          <div className="chart-tip" style={{ left: tipOnLeft ? undefined : x(hover) + 12, right: tipOnLeft ? width - x(hover) + 12 : undefined, top: MARGIN.top }}>
            <b>{longFormat.format(point.at)}</b>
            <span>{plural(point.total, "open finding")}</span>
          </div>
        )}
      </div>
      <div className="chart-legend" aria-hidden="true">
        {SEVERITIES.map((level) => <span key={level}><i className={`bar-${level}`}/>{level}<b>{point.counts[level]}</b></span>)}
        <small>{hover === null ? "Today" : dayFormat.format(point.at)}</small>
      </div>
      <p className="sr-only" aria-live="polite">{hover === null ? "" : `${longFormat.format(point.at)}: ${plural(point.total, "open finding")}. ${summary(point.counts)}.`}</p>
    </div>
  );
}

/** How long the open findings have been open, split by severity. */
export function AgeBars({ buckets }: { buckets: AgeBucket[] }) {
  const tallest = Math.max(1, ...buckets.map((bucket) => bucket.total));
  return (
    <div className="age-bars">
      {buckets.map((bucket) => (
        <div className="age-row" key={bucket.label}>
          <span>{bucket.label}</span>
          <span className="age-track" role="img" aria-label={`${bucket.label}: ${plural(bucket.total, "finding")} (${summary(bucket.counts)})`}>
            <span className="age-fill" style={{ width: `${(bucket.total / tallest) * 100}%` }}>
              {(SEVERITIES as readonly Severity[]).filter((level) => bucket.counts[level]).map((level) => <i key={level} className={`bar-${level}`} style={{ flex: bucket.counts[level] }}/>)}
            </span>
          </span>
          <b>{bucket.total}</b>
        </div>
      ))}
    </div>
  );
}

export const WINDOWS = [{ value: "30", label: "30 days" }, { value: "90", label: "90 days" }, { value: "180", label: "180 days" }] as const;
