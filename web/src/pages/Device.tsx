import { useDevice, useRevokeDevice, type Host } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, ago, shortDigest } from "../ui";

function Harnesses({ h }: { h: Host }) {
  const rows = Object.entries(h.harnesses);
  if (rows.length === 0) return <span className="text-mute">—</span>;
  return (
    <>
      {rows.map(([n, s]) => (
        <div key={n} className="flex items-center gap-2">
          <span className="w-24 text-mute">{n}</span>
          <Mono className={s.installed === s.want ? "" : "text-amber-500"}>{s.installed || "missing"}</Mono>
          {s.installed !== s.want && <span className="text-mute">→ <Mono>{s.want}</Mono> (version mismatch)</span>}
        </div>
      ))}
    </>
  );
}

export function Device({ id }: { id: string }) {
  const { data, error, isLoading } = useDevice(id);
  const revoke = useRevokeDevice();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const { device: d, last, history } = data;
  return (
    <div className="space-y-5">
      <a href="#/fleet" className="text-mute hover:text-fg">← Fleet</a>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">{last?.hostname ?? "Device"}</h2>
        <Mono className="text-mute">{d.id}</Mono>
        {d.revoked ? <Pill tone="bad" dot>revoked</Pill> : <Pill tone="ok" dot>active</Pill>}
        {last?.errorCode && <Pill tone="bad">error: {last.errorCode}</Pill>}
        {!d.revoked && (
          <button
            className="ml-auto rounded-md border border-line px-3 py-1.5 hover:bg-panel2 disabled:opacity-50"
            disabled={revoke.isPending}
            onClick={() => { if (window.confirm(`Revoke ${last?.hostname ?? "this device"}? Its token stops working at once: halod on it can no longer fetch releases or report, and the gateway's posture check fails for ${d.userID} until they re-enroll from the Kiosk. This cannot be undone.`)) revoke.mutate(d.id); }}
          >
            {revoke.isPending ? "Revoking…" : "Revoke device"}
          </button>
        )}
      </div>
      {revoke.error && <ErrorBox error={revoke.error} />}
      {d.revoked && <div className="text-mute">Revoked. The machine must re-enroll from the Kiosk (Set up my laptop) to be managed again.</div>}

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Binding">
          <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 p-4">
            <dt className="text-mute">User</dt><dd>{d.userID}</dd>
            <dt className="text-mute">Enrolled</dt><dd>{new Date(d.createdAt).toLocaleString()}</dd>
            <dt className="text-mute">Last seen</dt><dd>{ago(d.lastSeen)}</dd>
            <dt className="text-mute">Token expires</dt><dd>{d.expiresAt ? new Date(d.expiresAt).toLocaleString() : "—"}</dd>
            <dt className="text-mute">Groups</dt><dd>{d.groups.join(", ") || "—"}</dd>
          </dl>
        </Card>
        <Card title="Last report">
          {!last ? <Empty>No report received yet: halod has not run on this machine since enrollment.</Empty> : (
            <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 p-4">
              <dt className="text-mute">Ring</dt><dd><Pill tone="info">{last.ring || "—"}</Pill></dd>
              <dt className="text-mute">Release</dt><dd><Mono>{shortDigest(last.digest)}</Mono></dd>
              <dt className="text-mute">Harnesses</dt><dd><Harnesses h={last} /></dd>
              <dt className="text-mute">Drift</dt><dd>{last.drift.length ? <div className="flex flex-wrap gap-1">{last.drift.map((x) => <Pill key={x} tone="warn">{x}</Pill>)}</div> : "—"}</dd>
              <dt className="text-mute">Error</dt><dd>{last.errorCode || last.lastError ? <div>{last.errorCode && <Mono>{last.errorCode}</Mono>}{last.lastError && <div className="text-rose-500">{last.lastError}</div>}</div> : "—"}</dd>
            </dl>
          )}
        </Card>
      </div>

      <Card title={`Report history · ${history.length}`} right={<span className="text-mute">newest first, bounded; resets on server restart</span>}>
        {history.length === 0 ? <Empty>No report yet. halod reports after each run; on the machine: <Mono>sudo halod once</Mono>.</Empty> : (
          <div className="overflow-x-auto"><table className="w-full text-left">
            <caption className="sr-only">Recent reports from this device</caption>
            <thead className="text-[11px] tracking-wide text-mute uppercase">
              <tr className="border-b border-line">{["Received", "Release", "Harnesses", "Drift", "Error"].map((c) => <th key={c} scope="col" className="px-4 py-2 font-medium">{c}</th>)}</tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={`${h.lastSeen}-${i}`} className="border-b border-line last:border-0 align-top">
                  <td className="px-4 py-2 whitespace-nowrap text-mute" title={h.lastSeen}>{ago(h.lastSeen)}</td>
                  <td className="px-4 py-2"><Mono>{shortDigest(h.digest)}</Mono></td>
                  <td className="px-4 py-2"><Harnesses h={h} /></td>
                  <td className="px-4 py-2">{h.drift.length || "—"}</td>
                  <td className="px-4 py-2">{h.errorCode ? <Pill tone="bad">{h.errorCode}</Pill> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
    </div>
  );
}
