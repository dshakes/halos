import { useCapabilities, useExperiments, useFleet, useKills, usePolicy, useReleases, useRequests, type RingRelease, type RingStats } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, shortDigest, statusTone, type Tone } from "../ui";

function top(m: Record<string, number>): [string, number][] {
  return Object.entries(m).sort((a, b) => b[1] - a[1]);
}

function Track({ name, order, stats, target, release, profile }: { name: string; order: number; stats?: RingStats; target?: number; release?: RingRelease; profile: string }) {
  const pct = stats?.percent ?? 0;
  const current = release?.published ? release.digest : undefined;
  // A device on one of the ring's experiment channels is on policy; only an unknown digest is worth amber.
  const known = new Set([current, ...(release?.channels ?? []).filter((c) => c.published).map((c) => c.digest)]);
  const digestDrift = stats && current && Object.keys(stats.digests).some((d) => !known.has(d));
  return (
    <div className="grid items-center gap-3 border-b border-line px-4 py-3.5 last:border-0 md:grid-cols-[180px_1fr_auto] md:gap-5">
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
                  {i > 0 && ", "}{v || "not installed"}<span className="text-mute">×{n}</span>
                </Mono>
              ))}
            </span>
          ))}
          {!stats && <span className="text-mute">no devices reporting</span>}
        </div>
      </div>
      <div className="flex flex-col gap-1 md:min-w-40 md:items-end md:text-right">
        <div>
          <span className="text-lg font-semibold tabular-nums">{pct.toFixed(0)}%</span> <span className="text-mute">{stats?.hosts ?? 0} device{stats?.hosts === 1 ? "" : "s"}</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {current ? <Mono className={digestDrift ? "text-amber-600 dark:text-amber-300" : "text-mute"} title={digestDrift ? "some devices run a release that is neither this one nor one of its experiment channels" : "current signed release"}>{shortDigest(current)}</Mono> : release?.error ? <Pill tone="warn">pointer not readable</Pill> : <Pill>no release published</Pill>}
          {release?.expired ? <Pill tone="bad">release expired</Pill> : release?.expiringSoon ? <Pill tone="warn">expiring soon</Pill> : null}
          {stats && stats.driftHosts > 0 ? <Pill tone="warn" dot>{stats.driftHosts} drift</Pill> : stats ? <Pill tone="ok" dot>in sync</Pill> : null}
        </div>
      </div>
    </div>
  );
}

function Tile({ label, value, tone, href, hint }: { label: string; value: string | number; tone?: Tone; href?: string; hint?: string }) {
  const body = (
    <>
      <div className="text-mute">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${tone === "bad" ? "text-rose-600 dark:text-rose-300" : tone === "warn" ? "text-amber-600 dark:text-amber-300" : ""}`}>{value}</div>
      {hint && <div className="mt-0.5 truncate text-[11px] text-mute" title={hint}>{hint}</div>}
    </>
  );
  return href ? <a href={href} className="block rounded-lg border border-line bg-panel px-4 py-3 hover:bg-panel2">{body}</a> : <Card className="px-4 py-3">{body}</Card>;
}

export function Overview() {
  const policy = usePolicy();
  const fleet = useFleet();
  const exps = useExperiments();
  const rels = useReleases();
  const reqs = useRequests();
  const caps = useCapabilities();
  const kills = useKills(caps.data?.killSwitch === true);
  if (policy.error) return <ErrorBox error={policy.error} />;
  const stats = new Map((fleet.data?.rings ?? []).map((r) => [r.ring, r]));
  const relByRing = new Map((rels.data?.rings ?? []).map((r) => [r.ring, r]));
  const running = (exps.data ?? []).filter((e) => e.status === "running");
  const pending = (reqs.data ?? []).filter((r) => r.status === "pending").length;
  const badRel = (rels.data?.rings ?? []).filter((r) => r.expired || r.suspicious || r.error).length;
  const soonRel = (rels.data?.rings ?? []).filter((r) => r.expiringSoon && !r.expired).length;
  const killed = (kills.data?.killed ?? []).filter((k) => k.killed).length;
  const drift = fleet.data?.driftHosts ?? 0;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <Tile label="Devices reporting" value={fleet.data?.total ?? "—"} href="#/fleet" hint={fleet.data?.total === 0 ? "none yet" : undefined} />
        <Tile label="With drift" value={fleet.data?.driftHosts ?? "—"} tone={drift > 0 ? "warn" : undefined} href="#/fleet" hint={drift > 0 ? "halod restores on next run" : "settings match policy"} />
        <Tile label="Releases" value={rels.data ? (badRel > 0 ? `${badRel} broken` : soonRel > 0 ? `${soonRel} expiring` : "healthy") : "—"} tone={badRel > 0 ? "bad" : soonRel > 0 ? "warn" : undefined} href="#/releases" hint={rels.data ? `${rels.data.rings.filter((r) => r.published).length}/${rels.data.rings.length} rings published` : undefined} />
        <Tile label="Running experiments" value={exps.data ? running.length : "—"} href="#/experiments" />
        <Tile label="Pending approvals" value={reqs.data ? pending : "—"} tone={pending > 0 ? "warn" : undefined} href="#/approvals" hint={pending > 0 ? "developers are waiting" : "inbox zero"} />
        <Tile label="Kill switch" value={caps.data?.killSwitch ? (kills.data ? (killed === 0 ? "armed, idle" : `${killed} killed`) : "—") : "not configured"} tone={killed > 0 ? "bad" : undefined} href="#/experiments" hint={caps.data?.killSwitch ? "stops an experiment fleet-wide in ~60 s" : "start halo-server with a kill key"} />
      </div>
      {fleet.data?.total === 0 && (
        <Card className="px-4 py-3 text-mute">
          <span className="font-medium text-fg">No device has reported yet.</span> Developers enroll their own machines from the <a className="text-accent hover:underline" href="#/kiosk">Kiosk</a> (Set up my laptop); dev containers report through the fleet token. To test from a machine by hand: <Mono className="text-fg">sudo halod once</Mono>.
        </Card>
      )}
      <Card title="Rollout rings" right={<span className="text-mute">share of fleet per ring · current release</span>}>
        {policy.data?.rings.length ? (
          policy.data.rings.map((r) => (
            <Track key={r.name} name={r.name} order={r.order} stats={stats.get(r.name)} target={r.membership.percent} release={relByRing.get(r.name)} profile={r.profile} />
          ))
        ) : (
          <Empty>{policy.isLoading ? "Loading…" : <>No rings defined. Add one under <Mono>rings:</Mono> in the policy repo, then run <Mono>halo validate</Mono>.</>}</Empty>
        )}
        {[...stats.values()].filter((s) => !policy.data?.rings.some((r) => r.name === s.ring)).map((s) => (
          <Track key={s.ring} name={s.ring || "(none)"} order={0} stats={s} profile="not in policy" />
        ))}
      </Card>
      <Card title="Experiments" right={<a href="#/experiments" className="text-accent hover:underline">all →</a>}>
        {exps.error ? <ErrorBox error={exps.error} /> : exps.isLoading ? <Empty>Loading…</Empty> : (exps.data ?? []).length === 0 ? <Empty>No experiments. Define one under <Mono>experiments:</Mono> in the policy repo; it starts from the Experiments page as a PR.</Empty> : (
          <ul>
            {(exps.data ?? []).map((e) => (
              <li key={e.name} className="border-b border-line last:border-0">
                <a href={`#/experiments/${encodeURIComponent(e.name)}`} className="flex flex-wrap items-center gap-3 px-4 py-2.5 hover:bg-panel2">
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
