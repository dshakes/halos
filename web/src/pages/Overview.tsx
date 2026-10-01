import { useExperiments, useFleet, usePolicy, type RingStats } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, shortDigest, statusTone } from "../ui";

function top(m: Record<string, number>): [string, number][] {
  return Object.entries(m).sort((a, b) => b[1] - a[1]);
}

function Track({ name, order, stats, target, release, profile }: { name: string; order: number; stats?: RingStats; target?: number; release?: string; profile: string }) {
  const pct = stats?.percent ?? 0;
  const digest = stats ? top(stats.digests)[0]?.[0] : undefined;
  const pinned = release ? shortDigest(release) : "unpinned";
  const digestDrift = stats && release && Object.keys(stats.digests).some((d) => d !== release);
  return (
    <div className="grid grid-cols-[180px_1fr_auto] items-center gap-5 border-b border-line px-4 py-3.5 last:border-0">
      <div>
        <div className="flex items-center gap-2">
          <span className="grid size-5 place-items-center rounded bg-panel2 font-mono text-[10px] text-mute">{order}</span>
          <span className="font-medium">{name}</span>
        </div>
        <div className="mt-1 text-mute">
          {profile}
          {target !== undefined && target > 0 && <> · target {target}%</>}
        </div>
      </div>
      <div>
        <div className="relative">
          <div className="rail w-full" />
          <div className="rail rail-fill absolute inset-y-0 left-0 transition-all" style={{ width: `${pct}%` }} />
          {pct > 0 && <div className="absolute top-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-sm bg-accent" style={{ left: `${Math.min(pct, 100)}%` }} />}
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
          {stats && Object.entries(stats.versions).map(([h, vs]) => (
            <span key={h} className="text-mute">
              {h}{" "}
              {top(vs).map(([v, n], i) => (
                <Mono key={v} className="text-fg">
                  {i > 0 && ", "}{v || "?"}<span className="text-mute">×{n}</span>
                </Mono>
              ))}
            </span>
          ))}
          {!stats && <span className="text-mute">no hosts reporting</span>}
        </div>
      </div>
      <div className="flex min-w-40 flex-col items-end gap-1 text-right">
        <div>
          <span className="text-lg font-semibold tabular-nums">{pct.toFixed(0)}%</span> <span className="text-mute">{stats?.hosts ?? 0} hosts</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Mono className={digestDrift ? "text-amber-500" : "text-mute"} >{digest ? shortDigest(digest) : pinned}</Mono>
          {stats && stats.driftHosts > 0 ? <Pill tone="warn" dot>{stats.driftHosts} drift</Pill> : stats ? <Pill tone="ok" dot>in sync</Pill> : null}
        </div>
      </div>
    </div>
  );
}

export function Overview() {
  const policy = usePolicy();
  const fleet = useFleet();
  const exps = useExperiments();
  if (policy.error) return <ErrorBox error={policy.error} />;
  const stats = new Map((fleet.data?.rings ?? []).map((r) => [r.ring, r]));
  const running = (exps.data ?? []).filter((e) => e.status === "running");
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-4 gap-3">
        {[
          ["Hosts", fleet.data?.total ?? "—"],
          ["With drift", fleet.data?.driftHosts ?? "—"],
          ["Rings", policy.data?.rings.length ?? "—"],
          ["Running experiments", exps.data ? running.length : "—"],
        ].map(([k, v]) => (
          <Card key={k} className="px-4 py-3">
            <div className="text-mute">{k}</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums">{v}</div>
          </Card>
        ))}
      </div>
      <Card title="Rollout rings" right={<span className="text-mute">share of fleet per ring</span>}>
        {policy.data?.rings.length ? (
          policy.data.rings.map((r) => (
            <Track key={r.name} name={r.name} order={r.order} stats={stats.get(r.name)} target={r.membership.percent} release={r.release} profile={r.profile} />
          ))
        ) : (
          <Empty>{policy.isLoading ? "Loading…" : "No rings defined."}</Empty>
        )}
        {[...stats.values()].filter((s) => !policy.data?.rings.some((r) => r.name === s.ring)).map((s) => (
          <Track key={s.ring} name={s.ring || "(none)"} order={0} stats={s} profile="not in policy" />
        ))}
      </Card>
      <Card title="Experiments" right={<a href="#/experiments" className="text-accent hover:underline">all →</a>}>
        {exps.error ? <ErrorBox error={exps.error} /> : (exps.data ?? []).length === 0 ? <Empty>No experiments.</Empty> : (
          <ul>
            {(exps.data ?? []).map((e) => (
              <li key={e.name} className="border-b border-line last:border-0">
                <a href={`#/experiments/${encodeURIComponent(e.name)}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-panel2">
                  <Pill tone={statusTone(e.status)} dot>{e.status}</Pill>
                  <span className="font-medium">{e.name}</span>
                  <span className="text-mute">{e.type} · {e.axis}</span>
                  <span className="ml-auto flex items-center gap-2 text-mute">
                    {e.rings.join(", ")}
                    {e.verdict && <Pill tone={statusTone(e.verdict.verdict)}>{e.verdict.verdict}</Pill>}
                  </span>
                </a>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
