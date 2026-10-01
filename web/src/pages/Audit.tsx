import { useState } from "react";
import { useAudit } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, ago } from "../ui";

const inputCls = "h-8 rounded-md border border-line bg-panel px-2.5 text-[13px] outline-none focus:border-accent";
const actions = ["login", "logout", "request.create", "request.approve", "request.deny", "device.enroll", "device.revoke", "session.revoke", "experiment.status", "experiment.kill", "experiment.unkill"];

export function Audit() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const { data, error, isLoading } = useAudit(actor.trim(), action);
  if (error) return <ErrorBox error={error} />;
  const entries = data ? [...data.entries].reverse() : [];
  return (
    <div className="space-y-5">
      {data && (
        data.verified ? (
          <div className="flex items-center gap-2"><Pill tone="ok" dot>Chain verified</Pill><span className="text-mute">{data.total} entries, head <Mono>{data.head.slice(0, 12)}</Mono></span></div>
        ) : (
          <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-rose-700 dark:text-rose-300">
            <Pill tone="bad" dot>Chain broken</Pill> <span className="ml-2">The audit log has been modified or is missing entries: {data.verifyError}</span>
          </div>
        )
      )}
      <Card
        title={`Audit log${data ? ` · ${entries.length}/${data.total}` : ""}`}
        right={
          <div className="flex items-center gap-2">
            <input className={`${inputCls} w-44`} placeholder="Actor (exact)" aria-label="Filter by actor" value={actor} onChange={(e) => setActor(e.target.value)} />
            <select className={inputCls} value={action} onChange={(e) => setAction(e.target.value)} aria-label="Filter by action">
              <option value="">All actions</option>
              {actions.map((a) => <option key={a}>{a}</option>)}
            </select>
          </div>
        }
      >
        {isLoading || !data ? <Empty>Loading…</Empty> : entries.length === 0 ? <Empty>No entries.</Empty> : (
          <table className="w-full text-left">
            <caption className="sr-only">Privileged actions, newest first</caption>
            <thead className="text-[11px] tracking-wide text-mute uppercase">
              <tr className="border-b border-line">{["#", "When", "Actor", "Action", "Target", "Details", "IP"].map((c) => <th key={c} scope="col" className="px-4 py-2 font-medium">{c}</th>)}</tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.seq} className="border-b border-line align-top last:border-0 hover:bg-panel2">
                  <td className="px-4 py-2 tabular-nums text-mute">{e.seq}</td>
                  <td className="px-4 py-2 whitespace-nowrap" title={e.time}>{ago(e.time)}</td>
                  <td className="px-4 py-2">{e.actor}</td>
                  <td className="px-4 py-2"><Pill tone={e.action.endsWith("revoke") || e.action.endsWith(".kill") ? "bad" : "info"}>{e.action}</Pill></td>
                  <td className="px-4 py-2"><Mono>{e.target || "—"}</Mono></td>
                  <td className="px-4 py-2 text-mute">
                    {Object.entries(e.details).filter(([, v]) => v !== "").map(([k, v]) => (
                      <div key={k}>{k}: {/^https?:\/\//.test(v) ? <a className="text-accent underline" href={v} target="_blank" rel="noreferrer">{v}</a> : v}</div>
                    ))}
                  </td>
                  <td className="px-4 py-2"><Mono className="text-mute">{e.ip || "—"}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
