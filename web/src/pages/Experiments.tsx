import { useState } from "react";
import { useCapabilities, useExperiments, useKillExperiment, useSetExperimentStatus, type Experiment, type SettableStatus } from "../api";
import { Card, Empty, ErrorBox, Forest, Mono, Pill, statusTone, type Tone } from "../ui";
import { KillSwitchPanel } from "./KillSwitch";

const pct = (x: number) => `${(x * 100).toFixed(2)}%`;

const transitions: { status: SettableStatus; label: string }[] = [
  { status: "running", label: "Start" },
  { status: "paused", label: "Pause" },
  { status: "concluded", label: "Conclude" },
];

/** Status changes open a policy-repo PR (a human merges); the kill switch is shown only when the server has it. */
function Actions({ e }: { e: Experiment }) {
  const setStatus = useSetExperimentStatus();
  const kill = useKillExperiment();
  const caps = useCapabilities();
  const [reason, setReason] = useState("");
  const btn = "rounded-md border border-line px-3 py-1.5 hover:bg-panel2 disabled:opacity-50";
  return (
    <Card title="Actions" right={<span className="text-mute">status changes open a policy PR; a human merges it</span>}>
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap gap-2" role="group" aria-label={`Change status of ${e.name}`}>
          {transitions.map((t) => (
            <button
              key={t.status}
              className={btn}
              disabled={setStatus.isPending || e.status === t.status}
              onClick={() => { if (window.confirm(`Open a PR setting ${e.name} to ${t.status}?`)) setStatus.mutate({ name: e.name, status: t.status }); }}
            >
              {t.label}
            </button>
          ))}
        </div>
        {setStatus.error && <ErrorBox error={setStatus.error} />}
        {setStatus.data && (
          <div role="status" className="text-mute">
            PR opened: {/^https?:\/\//.test(setStatus.data.prURL) ? <a className="text-accent underline" href={setStatus.data.prURL} target="_blank" rel="noreferrer">{setStatus.data.prURL}</a> : setStatus.data.prURL}
          </div>
        )}
        {caps.data?.killSwitch && (
          <div className="border-t border-line pt-3">
            <div className="flex flex-wrap items-center gap-2">
              <input className="h-8 w-64 rounded-md border border-line bg-panel px-2.5 text-[13px] outline-none focus:border-accent" placeholder="Reason (required)" aria-label="Kill switch reason" required value={reason} onChange={(ev) => setReason(ev.target.value)} />
              <button
                className="rounded-md bg-rose-600 px-3 py-1.5 font-medium text-white disabled:opacity-50"
                disabled={kill.isPending || reason.trim() === ""}
                onClick={() => { if (window.confirm(`Kill ${e.name}? Users fall back to control at the next poll (~10 s gateways, ~60 s devices).`)) kill.mutate({ name: e.name, reason: reason.trim() }); }}
              >
                Kill switch
              </button>
            </div>
            {kill.error && <div className="mt-2"><ErrorBox error={kill.error} /></div>}
            {kill.isSuccess && <div role="status" className="mt-2 text-mute">Kill switch engaged.</div>}
          </div>
        )}
      </div>
    </Card>
  );
}

function Detail({ e }: { e: Experiment }) {
  const v = e.verdict;
  const totalW = e.variants.reduce((a, x) => a + x.weight, 0) || 1;
  const s = e.stopping;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">{e.name}</h2>
        <Pill tone={statusTone(e.status)} dot>{e.status}</Pill>
        <Pill>{e.type}</Pill>
        <Pill>{e.axis}</Pill>
        <span className="text-mute">rings: {e.rings.join(", ") || "—"}</span>
      </div>

      <Actions e={e} />

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Variants">
          <ul>
            {e.variants.map((x) => (
              <li key={x.name} className="border-b border-line px-4 py-2.5 last:border-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{x.name}</span>
                  {x.control && <Pill tone="info">control</Pill>}
                  <span className="ml-auto tabular-nums text-mute">{((100 * x.weight) / totalW).toFixed(0)}%</span>
                </div>
                <div className="mt-1.5 h-1.5 rounded-full bg-panel2"><div className="h-full rounded-full bg-accent" style={{ width: `${(100 * x.weight) / totalW}%` }} /></div>
                <div className="mt-1.5 text-mute">
                  {x.profile && <>profile <Mono className="text-fg">{x.profile}</Mono></>}
                  {Object.entries(x.routes).map(([a, r]) => <div key={a}><Mono>{a}</Mono> → <Mono className="text-fg">{r.upstream}:{r.model}</Mono></div>)}
                </div>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Stopping rule">
          <dl className="grid grid-cols-2 gap-y-2 p-4">
            {([["Method", s.method], ["Alpha", s.alpha], ["Min samples", s.minSamples], ["Max days", s.maxDays], ["Max spend", s.maxSpendUSD === undefined ? undefined : `$${s.maxSpendUSD}`], ["Shadow sample", e.sampleRate === undefined ? undefined : pct(e.sampleRate)]] as const)
              .filter(([, val]) => val !== undefined)
              .map(([k, val]) => (<div key={k} className="contents"><dt className="text-mute">{k}</dt><dd className="tabular-nums">{val}</dd></div>))}
          </dl>
        </Card>
      </div>

      <Card title="Verdict" right={v && <Pill tone={statusTone(v.verdict)} dot>{v.verdict}</Pill>}>
        {!v ? <Empty>No analysis yet. Run <Mono>halo exp analyze</Mono> to produce a verdict.</Empty> : (
          <div className="space-y-4 p-4">
            <p>{v.reason}</p>
            <div className="text-mute">{v.control} (n={v.nControl}) vs {v.treatment} (n={v.nTreatment}){v.evaluatedAt && <> · evaluated {new Date(v.evaluatedAt).toLocaleString()}</>}</div>
            <div>
              <div className="mb-1 flex items-baseline gap-3">
                <span className="font-medium">{e.metrics.primary.metric}</span>
                <span className="text-mute">want {e.metrics.primary.direction}</span>
                <span className="ml-auto tabular-nums">effect <Mono>{v.effect.toPrecision(3)}</Mono> · p=<Mono>{v.pValue.toPrecision(3)}</Mono></span>
              </div>
              <Forest row={{ label: e.metrics.primary.metric, est: v.effect, lo: v.effectLower, hi: v.effectUpper, tone: "info" }} />
              {v.effectLower === undefined && <div className="text-mute">No confidence interval in the verdict file.</div>}
            </div>
          </div>
        )}
      </Card>

      <Card title="Guardrails" right={<span className="text-mute">regression vs control; dashed = max allowed</span>}>
        {e.metrics.guardrails.length === 0 ? <Empty>None.</Empty> : e.metrics.guardrails.map((g) => {
          const r = v?.guardrails.find((x) => x.metric === g.metric)?.result;
          const tone: Tone = r ? statusTone(r.status) : "mute";
          return (
            <div key={g.metric} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)_90px] items-center gap-4 border-b border-line px-4 py-2.5 last:border-0">
              <div><Mono>{g.metric}</Mono><div className="text-mute">{g.direction}{g.maxRegression !== undefined && <> · max {pct(g.maxRegression)}</>}</div></div>
              {r ? <div><Forest row={{ label: g.metric, est: r.regression, lo: r.lower, hi: r.upper, ref: r.maxRegression, tone }} /><div className="text-right text-mute tabular-nums">{pct(r.regression)} [{pct(r.lower)}, {pct(r.upper)}]</div></div> : <span className="text-mute">no data</span>}
              <div className="text-right"><Pill tone={tone} dot>{r?.status ?? "pending"}</Pill></div>
            </div>
          );
        })}
      </Card>
    </div>
  );
}

export function Experiments({ name }: { name?: string }) {
  const { data, error, isLoading } = useExperiments();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const sel = data.find((e) => e.name === name) ?? (name ? undefined : data[0]);
  return (
    <div className="space-y-5">
    <KillSwitchPanel />
    <div className="grid grid-cols-[260px_1fr] gap-5">
      <Card>
        {data.length === 0 && <Empty>No experiments.</Empty>}
        {data.map((e) => (
          <a key={e.name} href={`#/experiments/${encodeURIComponent(e.name)}`} className={`block border-b border-line px-4 py-2.5 last:border-0 hover:bg-panel2 ${sel?.name === e.name ? "bg-panel2" : ""}`}>
            <div className="truncate font-medium">{e.name}</div>
            <div className="mt-1 flex items-center gap-2"><Pill tone={statusTone(e.status)} dot>{e.status}</Pill><span className="text-mute">{e.type}</span>{e.verdict && <Pill tone={statusTone(e.verdict.verdict)}>{e.verdict.verdict}</Pill>}</div>
          </a>
        ))}
      </Card>
      {sel ? <Detail key={sel.name} e={sel} /> : <Empty>Experiment not found.</Empty>}
    </div>
    </div>
  );
}
