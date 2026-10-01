import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "bad" | "info" | "mute";
const tones: Record<Tone, string> = {
  ok: "bg-emerald-500/10 text-emerald-700 ring-emerald-500/25 dark:text-emerald-300",
  warn: "bg-amber-500/10 text-amber-700 ring-amber-500/25 dark:text-amber-300",
  bad: "bg-rose-500/10 text-rose-700 ring-rose-500/25 dark:text-rose-300",
  info: "bg-indigo-500/10 text-indigo-700 ring-indigo-500/25 dark:text-indigo-300",
  mute: "bg-zinc-500/10 text-mute ring-zinc-500/20",
};

export function Pill({ tone = "mute", children, dot }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${tones[tone]}`}>
      {dot && <span className="size-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

export const statusTone = (s: string): Tone =>
  s === "running" || s === "pass" || s === "promote" ? "ok" : s === "paused" || s === "inconclusive" || s === "expired" ? "warn" : s === "fail" || s === "rollback" ? "bad" : s === "concluded" || s === "continue" ? "info" : "mute";

export function Card({ title, right, children, className = "" }: { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-line bg-panel ${className}`}>
      {title && (
        <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="text-[12px] font-medium tracking-wide text-mute uppercase">{title}</h2>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export const Mono = ({ children, className = "" }: { children: ReactNode; className?: string }) => <span className={`font-mono text-[12px] ${className}`}>{children}</span>;

export const shortDigest = (d: string) => (d ? d.replace(/^sha256:/, "").slice(0, 8) : "—");

export function ago(iso: string, now = Date.now()): string {
  const s = Math.max(0, (now - Date.parse(iso)) / 1000);
  if (Number.isNaN(s)) return "—";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const Empty = ({ children }: { children: ReactNode }) => <div className="px-4 py-10 text-center text-mute">{children}</div>;

export const ErrorBox = ({ error }: { error: unknown }) => (
  <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-rose-700 dark:text-rose-300">{error instanceof Error ? error.message : String(error)}</div>
);

const palette = ["#6366f1", "#10b981", "#f59e0b", "#ec4899", "#06b6d4", "#84cc16", "#f97316", "#8b5cf6"];
export const colorFor = (i: number) => palette[i % palette.length];

/** Stacked horizontal bar of counts. */
export function StackBar({ parts }: { parts: { label: string; n: number }[] }) {
  const total = parts.reduce((a, p) => a + p.n, 0) || 1;
  return (
    <div className="flex h-2 w-full overflow-hidden rounded-full bg-panel2">
      {parts.map((p, i) => (
        <div key={p.label} title={`${p.label}: ${p.n}`} style={{ width: `${(100 * p.n) / total}%`, background: colorFor(i) }} />
      ))}
    </div>
  );
}

export interface ForestRowData {
  label: string;
  est: number;
  lo?: number;
  hi?: number;
  /** vertical reference line (e.g. a guardrail's max regression) */
  ref?: number;
  tone: Tone;
}

const stroke: Record<Tone, string> = { ok: "#10b981", warn: "#f59e0b", bad: "#f43f5e", info: "#6366f1", mute: "#a1a1aa" };

/** One forest-plot row: point estimate, CI whisker, zero line, optional reference line. Each row has its own scale. */
export function Forest({ row }: { row: ForestRowData }) {
  const vals = [0, row.est, row.lo ?? row.est, row.hi ?? row.est, ...(row.ref === undefined ? [] : [row.ref])];
  let min = Math.min(...vals);
  let max = Math.max(...vals);
  const pad = (max - min || 1) * 0.15;
  min -= pad;
  max += pad;
  const x = (v: number) => ((v - min) / (max - min)) * 300;
  const c = stroke[row.tone];
  return (
    <svg viewBox="0 0 300 24" className="h-6 w-full" role="img" aria-label={`${row.label} estimate ${row.est}`}>
      <line x1={x(0)} x2={x(0)} y1="2" y2="22" stroke="currentColor" className="text-mute" strokeOpacity=".5" />
      {row.ref !== undefined && <line x1={x(row.ref)} x2={x(row.ref)} y1="2" y2="22" stroke="#f43f5e" strokeDasharray="3 2" />}
      {row.lo !== undefined && row.hi !== undefined && (
        <>
          <line x1={x(row.lo)} x2={x(row.hi)} y1="12" y2="12" stroke={c} strokeWidth="2" strokeLinecap="round" />
          <line x1={x(row.lo)} x2={x(row.lo)} y1="8" y2="16" stroke={c} strokeWidth="2" />
          <line x1={x(row.hi)} x2={x(row.hi)} y1="8" y2="16" stroke={c} strokeWidth="2" />
        </>
      )}
      <rect x={x(row.est) - 4} y="8" width="8" height="8" transform={`rotate(45 ${x(row.est)} 12)`} fill={c} />
    </svg>
  );
}
