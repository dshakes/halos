import { useReleases, type ChannelRelease, type RingRelease } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, StackBar, ago, shortDigest, type Tone } from "../ui";

function span(sec: number): string {
  const s = Math.abs(sec);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${Math.floor((s % 3600) / 60)}m` : `${Math.floor(s / 60)}m`;
}

/** Expiry badge: amber <48h, red once expired; always carries a text label, never colour alone. */
export function ExpiryBadge({ r }: { r: RingRelease }) {
  if (!r.published) return <Pill>no pointer</Pill>;
  const tone: Tone = r.expired ? "bad" : r.expiringSoon ? "warn" : "ok";
  const label = r.expired ? `Expired ${span(r.expiresInSeconds)} ago` : r.expiringSoon ? `Expiring soon · ${span(r.expiresInSeconds)} left` : `${span(r.expiresInSeconds)} left`;
  return <Pill tone={tone} dot>{label}</Pill>;
}

/** One experiment channel's pointer under a ring; text + colour for expiry and suspicion. */
function ChannelRow({ c }: { c: ChannelRelease }) {
  return (
    <li className="flex flex-wrap items-center gap-2">
      <Mono>{c.channel}</Mono>
      {c.published ? <Mono>{shortDigest(c.digest ?? "")}</Mono> : <Pill>no pointer</Pill>}
      {c.published && c.seq !== undefined && <span className="tabular-nums text-mute">seq {c.seq}</span>}
      {c.expired ? <Pill tone="bad" dot>Expired{c.expiresAt ? ` ${new Date(c.expiresAt).toLocaleString()}` : ""}</Pill> : c.published && c.expiresAt && <span className="text-mute">expires {new Date(c.expiresAt).toLocaleString()}</span>}
      {c.suspicious && <Pill tone="bad" dot>Suspicious pointer</Pill>}
      {c.stale && <Pill tone="warn">cached</Pill>}
      <span className="tabular-nums text-mute">{c.devices} device{c.devices === 1 ? "" : "s"}</span>
      {c.error && <span role="alert" className="text-amber-700 dark:text-amber-300">{c.error}</span>}
    </li>
  );
}

function RingCard({ r }: { r: RingRelease }) {
  const c = r.convergence;
  const pct = c.total === 0 ? 0 : Math.round((100 * c.onDigest) / c.total);
  const others = Object.entries(c.digests).filter(([d]) => d !== r.digest).sort((a, b) => b[1] - a[1]);
  return (
    <Card
      title={r.ring}
      right={
        <div className="flex items-center gap-2">
          {r.suspicious && <Pill tone="bad" dot>Suspicious pointer · last good shown</Pill>}
          {r.stale && <Pill tone="warn">cached · registry unreachable</Pill>}
          <ExpiryBadge r={r} />
        </div>
      }
    >
      <div className="space-y-4 p-4">
        {r.error && <div role="alert" className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-amber-700 dark:text-amber-300">Pointer not refreshed: {r.error}</div>}
        {r.published ? (
          <dl className="grid grid-cols-[90px_1fr] gap-y-1.5">
            <dt className="text-mute">Release</dt><dd><Mono>{shortDigest(r.digest ?? "")}</Mono></dd>
            <dt className="text-mute">Seq</dt><dd className="tabular-nums">{r.seq}</dd>
            <dt className="text-mute">Org</dt><dd>{r.org}</dd>
            <dt className="text-mute">Issued</dt><dd>{r.issuedAt ? ago(r.issuedAt) : "—"}</dd>
            <dt className="text-mute">Expires</dt><dd>{r.expiresAt ? new Date(r.expiresAt).toLocaleString() : "—"}</dd>
          </dl>
        ) : !r.error && <div className="text-mute">No signed pointer published for this ring.</div>}

        {r.channels.length > 0 && (
          <div>
            <div className="mb-1.5 font-medium">Experiment channels</div>
            <ul className="space-y-1">{r.channels.map((c) => <ChannelRow key={c.channel} c={c} />)}</ul>
          </div>
        )}

        <div>
          <div className="mb-1.5 flex items-baseline justify-between">
            <span className="font-medium">Convergence</span>
            <span className="tabular-nums text-mute">{c.onDigest}/{c.total} on current release{c.total > 0 && ` (${pct}%)`}</span>
          </div>
          <div role="img" aria-label={`${c.onDigest} of ${c.total} devices on the current release, ${c.other} on other releases`}>
            <StackBar parts={[{ label: "current release", n: c.onDigest }, { label: "other releases", n: c.other }]} />
          </div>
          {others.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-mute">
              {others.map(([d, n]) => <li key={d}><Mono>{shortDigest(d)}</Mono> · {n} device{n === 1 ? "" : "s"}</li>)}
            </ul>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-mute">Drift</span>
          {r.driftHosts > 0 ? <Pill tone="warn" dot>{r.driftHosts} host{r.driftHosts === 1 ? "" : "s"} drifted</Pill> : <Pill tone="ok" dot>none</Pill>}
        </div>
      </div>
    </Card>
  );
}

export function Releases() {
  const { data, error, isLoading } = useReleases();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3 text-mute">
        <span>Registry <Mono>{data.registry || "not configured"}</Mono></span>
        {data.stale && <Pill tone="warn" dot>showing cached state</Pill>}
        <span>Pointers are signature-verified before display.</span>
      </div>
      {data.rings.length === 0 ? <Empty>No rings in policy.</Empty> : <div className="grid gap-5 lg:grid-cols-2">{data.rings.map((r) => <RingCard key={r.ring} r={r} />)}</div>}
    </div>
  );
}
