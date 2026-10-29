import type { CSSProperties } from "react";

export type Blip = { id: string; severity: string };

// Urgency maps to range: critical findings sit closest to the core, low ones near the rim.
const bands: Record<string, [number, number]> = { critical: [24, 40], high: [44, 60], medium: [64, 78], low: [80, 90], unknown: [80, 92] };

function hash(value: string) {
  let result = 5381;
  for (let index = 0; index < value.length; index += 1) result = (result * 33) ^ value.charCodeAt(index);
  return result >>> 0;
}

export function Radar({ blips = [], className = "" }: { blips?: Blip[]; className?: string }) {
  return (
    <div className={`radar ${className}`} aria-hidden="true">
      <svg viewBox="-100 -100 200 200">
        {[96, 68, 40].map((radius) => <circle key={radius} className="radar-ring" r={radius}/>)}
        <line className="radar-axis" x1={-100} y1={0} x2={100} y2={0}/>
        <line className="radar-axis" x1={0} y1={-100} x2={0} y2={100}/>
        {blips.slice(0, 48).map((blip, index) => {
          const seed = hash(blip.id);
          const [inner, outer] = bands[blip.severity] ?? bands.unknown;
          const angle = ((seed % 3600) / 10) * (Math.PI / 180);
          const distance = inner + ((seed >>> 12) % 100) / 100 * (outer - inner);
          const style = { animationDelay: `${120 + index * 40}ms` } as CSSProperties;
          return <circle key={blip.id} className={`radar-blip ${blip.severity}`} style={style} cx={Math.cos(angle) * distance} cy={Math.sin(angle) * distance} r={blip.severity === "critical" ? 3.6 : 2.8}/>;
        })}
        <circle className="radar-core" r={2.6}/>
      </svg>
      <div className="radar-sweep"/>
    </div>
  );
}
