import { useDecide, useMe, useRequests } from "../api";
import { Card, Empty, ErrorBox, Pill, ago, statusTone } from "../ui";

export function Approvals() {
  const { data, error, isLoading } = useRequests();
  const decide = useDecide();
  const me = useMe().data;
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const pending = data.filter((r) => r.status === "pending" || r.status === "approving");
  const done = data.filter((r) => !pending.includes(r));
  return (
    <div className="space-y-5">
      {decide.error && <ErrorBox error={decide.error} />}
      <Card title={`Pending · ${pending.length}`} right={<span className="text-mute">approving opens a policy PR; a human merges it</span>}>
        {pending.length === 0 ? <Empty>Inbox zero. Developers' requests from the Kiosk land here.</Empty> : pending.map((r) => (
          <div key={r.id} className="grid items-center gap-3 border-b border-line px-4 py-3 last:border-0 md:grid-cols-[1fr_auto] md:gap-4">
            <div>
              <div className="flex flex-wrap items-center gap-2"><span className="font-medium">{r.user}</span><Pill>{r.kind}</Pill><span className="font-mono text-[12px]">{r.item}</span><span className="text-mute">{r.ring} · {ago(r.createdAt)}</span></div>
              <p className="mt-1 text-mute">{r.justification}</p>
            </div>
            {/* The server refuses self-decisions (403) and anything not pending (409): offer neither. */}
            {r.status !== "pending" ? <Pill tone="info">approved · opening PR…</Pill> : r.user === me?.id ? <span className="text-mute">your own request: another admin decides</span> : (
              <div className="flex gap-2">
                <button disabled={decide.isPending} onClick={() => { if (window.confirm(`Deny ${r.user}'s request for ${r.item}? They see the denial on their Kiosk and can ask again.`)) decide.mutate({ id: r.id, action: "deny" }); }} className="rounded-md border border-line px-3 py-1.5 hover:bg-panel2 disabled:opacity-50">Deny</button>
                <button disabled={decide.isPending} title="Opens a policy-repo PR with the change; nothing applies until someone merges it" onClick={() => decide.mutate({ id: r.id, action: "approve" })} className="rounded-md bg-accent px-3 py-1.5 font-medium text-white disabled:opacity-50">{decide.isPending ? "Working…" : "Approve → open PR"}</button>
              </div>
            )}
          </div>
        ))}
      </Card>
      <Card title="Decided">
        {done.length === 0 ? <Empty>Nothing decided yet.</Empty> : done.map((r) => (
          <div key={r.id} className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2.5 last:border-0">
            <Pill tone={statusTone(r.status === "approved" ? "pass" : "fail")} dot>{r.status}</Pill>
            <span>{r.user}</span><span className="text-mute">{r.kind}</span><span className="font-mono text-[12px]">{r.item}</span>
            {/* prURL is a link on GitHub-backed repos; a plain description (e.g. a local branch) elsewhere. Either way the admin sees where the change went. */}
            <span className="ml-auto text-mute">{r.decidedBy}{r.prURL && (/^https?:\/\//.test(r.prURL) ? <> · <a className="text-accent hover:underline" href={r.prURL} target="_blank" rel="noopener noreferrer">PR</a></> : <> · change proposed: {r.prURL}</>)}{r.note && ` · ${r.note}`}</span>
          </div>
        ))}
      </Card>
    </div>
  );
}
