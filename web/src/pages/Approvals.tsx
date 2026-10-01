import { useDecide, useRequests } from "../api";
import { Card, Empty, ErrorBox, Pill, ago, statusTone } from "../ui";

export function Approvals() {
  const { data, error, isLoading } = useRequests();
  const decide = useDecide();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const pending = data.filter((r) => r.status === "pending" || r.status === "approving");
  const done = data.filter((r) => !pending.includes(r));
  return (
    <div className="space-y-5">
      {decide.error && <ErrorBox error={decide.error} />}
      <Card title={`Pending · ${pending.length}`} right={<span className="text-mute">approving opens a policy PR; a human merges it</span>}>
        {pending.length === 0 ? <Empty>Inbox zero.</Empty> : pending.map((r) => (
          <div key={r.id} className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-line px-4 py-3 last:border-0">
            <div>
              <div className="flex items-center gap-2"><span className="font-medium">{r.user}</span><Pill>{r.kind}</Pill><span className="font-mono text-[12px]">{r.item}</span><span className="text-mute">{r.ring} · {ago(r.createdAt)}</span></div>
              <p className="mt-1 text-mute">{r.justification}</p>
            </div>
            <div className="flex gap-2">
              <button disabled={decide.isPending} onClick={() => decide.mutate({ id: r.id, action: "deny" })} className="rounded-md border border-line px-3 py-1.5 hover:bg-panel2 disabled:opacity-50">Deny</button>
              <button disabled={decide.isPending} onClick={() => decide.mutate({ id: r.id, action: "approve" })} className="rounded-md bg-accent px-3 py-1.5 font-medium text-white disabled:opacity-50">Approve</button>
            </div>
          </div>
        ))}
      </Card>
      <Card title="Decided">
        {done.length === 0 ? <Empty>Nothing yet.</Empty> : done.map((r) => (
          <div key={r.id} className="flex items-center gap-3 border-b border-line px-4 py-2.5 last:border-0">
            <Pill tone={statusTone(r.status === "approved" ? "pass" : "fail")} dot>{r.status}</Pill>
            <span>{r.user}</span><span className="text-mute">{r.kind}</span><span className="font-mono text-[12px]">{r.item}</span>
            <span className="ml-auto text-mute">{r.decidedBy}{r.prURL && /^https?:\/\//.test(r.prURL) && <> · <a className="text-accent hover:underline" href={r.prURL} target="_blank" rel="noopener noreferrer">PR</a></>}{r.note && ` · ${r.note}`}</span>
          </div>
        ))}
      </Card>
    </div>
  );
}
