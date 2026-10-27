import { useReleases, useRollout, useRollouts, type RolloutStep, type RolloutView } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, ago, shortDigest, type Tone } from "../ui";

const rolloutTone = (s: string): Tone => (s === "active" ? "ok" : s === "paused" ? "warn" : s === "aborted" ? "bad" : s === "completed" ? "info" : "mute");
const gateTone = (s: string): Tone => (s === "pass" ? "ok" : s === "fail" ? "bad" : "warn");

/** Mirrors policy.ParseBake: a Go duration or N"d". Returns ms, or undefined when empty/unparseable. */
function bakeMs(s?: string): number | undefined {
  if (!s) return undefined;
  const d = /^(\d+)d$/.exec(s);
  if (d) return Number(d[1]) * 86_400_000;
  const unit: Record<string, number> = { h: 3_600_000, m: 60_000, s: 1000 };
  const parts = [...s.matchAll(/(\d+(?:\.\d+)?)([hms])/g)];
  if (parts.length === 0 || parts.map((p) => p[0]).join("") !== s) return undefined;
  return parts.reduce((a, p) => a + Number(p[1]) * (unit[p[2] ?? ""] ?? 0), 0);
}

function left(ms: number): string {
  const m = Math.ceil(ms / 60_000);
  return m >= 1440 ? `${Math.floor(m / 1440)}d ${Math.floor((m % 1440) / 60)}h` : m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`;
}

function Timeline({ v, now }: { v: RolloutView; now: number }) {
  const st = v.state;
  return (
    <ol className="divide-y divide-line">
      {v.timeline.steps.map((s: RolloutStep) => {
        const live = s.live === true || (st != null && st.step === s.index);
        const done = st != null && st.step > s.index;
        const gates = live && st?.last?.step === s.index ? st.last.gates : [];
        const bake = bakeMs(s.bake);
        const remaining = live && st && bake !== undefined ? Date.parse(st.enteredAt) + bake - now : undefined;
        return (
          <li key={s.index} className="px-4 py-3" aria-current={live ? "step" : undefined}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="grid size-5 place-items-center rounded bg-panel2 font-mono text-[10px] text-mute">{s.index + 1}</span>
              <span className="font-medium">{s.name}</span>
              <Pill>{s.strategy}</Pill>
              {live ? <Pill tone={st?.halted ? "bad" : "info"} dot>{st?.halted ? `halted: ${st.halted}` : "current step"}</Pill> : done ? <Pill tone="ok">done</Pill> : <Pill>upcoming</Pill>}
              <span className="ml-auto text-mute">earliest {s.earliestStart}</span>
            </div>
            <div className="mt-1 text-mute">{s.exposure}</div>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              {s.bake && <Pill>bake {s.bake}</Pill>}
              {remaining !== undefined && (remaining > 0 ? <Pill tone="warn">{left(remaining)} left to bake</Pill> : <Pill tone="ok">bake elapsed</Pill>)}
              {s.minSamples ? <Pill>min {s.minSamples} samples</Pill> : null}
              <Pill>on failure: {s.onFailure}</Pill>
              {gates.length === 0 && s.gates.map((g) => <Pill key={g}>{g}</Pill>)}
              {gates.map((g) => (
                <Pill key={g.gate} tone={gateTone(g.status)}>
                  {g.gate}: {g.status}{g.value ? ` (${g.value}${g.threshold ? ` / ${g.threshold}` : ""})` : ""}
                </Pill>
              ))}
              {live && st?.last?.awaitingApproval && <Pill tone="warn" dot>awaiting human approval</Pill>}
            </div>
            {live && st?.last && st.last.reasons.length > 0 && <ul className="mt-2 list-disc pl-5 text-mute">{st.last.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
          </li>
        );
      })}
    </ol>
  );
}

export function Rollouts({ name }: { name?: string }) {
  return name ? <RolloutDetail name={name} /> : <RolloutList />;
}

function RolloutList() {
  const { data, error, isLoading } = useRollouts();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  return (
    <Card title={`Rollouts · ${data.length}`} right={<span className="text-mute">changes are driven by PRs; the controller never merges</span>}>
      {data.length === 0 ? <Empty>No rollouts defined. Add a <Mono>Rollout</Mono> to the policy repo, then run <Mono>halo rollout plan</Mono>.</Empty> : (
        <ul>
          {data.map((v) => {
            const status = v.timeline.status;
            const steps = v.timeline.steps;
            const live = steps.find((s) => s.live);
            return (
              <li key={v.rollout.name} className="border-b border-line last:border-0">
                <a href={`#/rollouts/${encodeURIComponent(v.rollout.name)}`} className="flex flex-wrap items-center gap-3 px-4 py-2.5 hover:bg-panel2">
                  <Pill tone={rolloutTone(status)} dot>{status}</Pill>
                  <span className="font-medium">{v.rollout.name}</span>
                  <span className="text-mute">{v.timeline.axis} · {v.timeline.change}</span>
                  <span className="ml-auto flex items-center gap-2 text-mute">
                    {live ? `step ${live.index + 1}/${steps.length}: ${live.name}` : "not started"}
                    {v.state?.halted && <Pill tone="bad">{v.state.halted}</Pill>}
                    {v.stateError && <Pill tone="warn">state unreadable</Pill>}
                  </span>
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

function RolloutDetail({ name }: { name: string }) {
  const { data: v, error, isLoading } = useRollout(name);
  const rels = useReleases();
  if (error) return <div className="space-y-5"><a href="#/rollouts" className="text-mute hover:text-fg">← Rollouts</a><ErrorBox error={error} /></div>;
  if (isLoading || !v) return <Empty>Loading…</Empty>;
  const now = Date.now();
  const st = v.state;
  const rings = [...new Set(v.timeline.steps.flatMap((s) => s.ring.split(",")).filter(Boolean))];
  const relByRing = new Map((rels.data?.rings ?? []).map((r) => [r.ring, r]));
  const events = (st?.history ?? []).filter((e) => e.event === "halt" || e.event === "resume").slice().reverse();
  return (
    <div className="space-y-5">
      <a href="#/rollouts" className="text-mute hover:text-fg">← Rollouts</a>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">{v.rollout.name}</h2>
        <Pill tone={rolloutTone(v.timeline.status)} dot>{v.timeline.status}</Pill>
        <span className="text-mute">{v.timeline.axis} · {v.timeline.change}</span>
        {v.rollout.experiment && <a className="text-accent hover:underline" href={`#/experiments/${encodeURIComponent(v.rollout.experiment)}`}>experiment {v.rollout.experiment}</a>}
        <span className="ml-auto text-mute">fastest finish {v.timeline.minDuration}</span>
      </div>
      {v.stateError && <ErrorBox error={`Controller state is unreadable: ${v.stateError}`} />}
      {!st && !v.stateError && <Card className="px-4 py-3 text-mute">No controller state yet: the rollout has not started, or halo-server is not running with <Mono>--controller</Mono>. The plan below is from policy.</Card>}
      {st?.halted && (
        <Card className="px-4 py-3">
          <Pill tone="bad" dot>halted: {st.halted}</Pill>
          <span className="ml-2 text-mute">{st.haltReason}{st.haltSource && ` (evidence: ${st.haltSource})`}. Resume by moving the rollout out of <Mono>active</Mono> in policy.</span>
        </Card>
      )}

      <Card title="Step timeline" right={st ? <span className="text-mute">entered {ago(st.enteredAt)} · decision {st.last?.action ?? "none"}</span> : undefined}>
        {v.timeline.steps.length === 0 ? <Empty>This rollout has no steps.</Empty> : <Timeline v={v} now={now} />}
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Rings → releases" right={<span className="text-mute">target <Mono>{shortDigest(v.rollout.change.release ?? "")}</Mono>{v.rollout.baseline?.release ? <> · baseline <Mono>{shortDigest(v.rollout.baseline.release)}</Mono></> : null}</span>}>
          {rels.error ? <ErrorBox error={rels.error} /> : rings.length === 0 ? <Empty>No ring is targeted by name; percent steps expose the backing experiment.</Empty> : (
            <ul>
              {rings.map((r) => {
                const rel = relByRing.get(r);
                const onTarget = !!rel?.digest && rel.digest === v.rollout.change.release;
                return (
                  <li key={r} className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2 last:border-0">
                    <span className="font-medium">{r}</span>
                    {rel?.published ? <Mono>{shortDigest(rel.digest ?? "")}</Mono> : <Pill>{rels.isLoading ? "loading" : "no release published"}</Pill>}
                    {rel?.published && <Pill tone={onTarget ? "ok" : "mute"}>{onTarget ? "on target" : "not on target"}</Pill>}
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card title="Rollback and halt events" right={<span className="text-mute">hash-chained history</span>}>
          {events.length === 0 ? <Empty>No rollback, pause or resume events.</Empty> : (
            <ul>
              {events.map((e) => (
                <li key={e.seq} className="border-b border-line px-4 py-2 last:border-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill tone={e.event === "halt" ? "bad" : "ok"}>{e.event === "halt" ? (e.detail ?? "halt") : "resumed"}</Pill>
                    {e.step && <span className="font-medium">{e.step}</span>}
                    <span className="ml-auto text-mute" title={e.at}>{ago(e.at)}</span>
                  </div>
                  {(e.reason || e.source) && <div className="mt-1 text-mute">{e.reason}{e.source && ` (evidence: ${e.source})`}</div>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
