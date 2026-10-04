import { useState } from "react";
import { useWhoami } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, shortDigest, statusTone } from "../ui";

const inputCls = "h-9 w-full rounded-md border border-line bg-panel px-3 text-[13px] outline-none focus:border-accent";

export function Debugger({ self }: { self?: string }) {
  const [user, setUser] = useState(self ?? "");
  const [groups, setGroups] = useState("");
  const [q, setQ] = useState({ user: self ?? "", groups: "" });
  const { data, error, isFetching } = useWhoami(q.user, q.groups);
  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Card title={self === undefined ? "Assignment debugger" : "Why do I get this setup?"} right={self === undefined && <span className="text-mute">resolve any user's ring and experiment variants</span>}>
        <form className="grid items-end gap-3 p-4 md:grid-cols-[1fr_1fr_auto]" onSubmit={(e) => { e.preventDefault(); setQ({ user: user.trim(), groups }); }}>
          <label className="space-y-1"><span className="text-mute">User id</span><input className={inputCls} value={user} onChange={(e) => setUser(e.target.value)} placeholder="alice@acme.com" readOnly={self !== undefined} autoFocus /></label>
          <label className="space-y-1"><span className="text-mute">IdP groups (comma-separated)</span><input className={inputCls} value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="harness-team, eng" disabled={self !== undefined} /></label>
          <button className="h-9 rounded-md bg-accent px-4 font-medium text-white disabled:opacity-50" disabled={!user.trim() || isFetching}>Resolve</button>
        </form>
      </Card>
      {error && <ErrorBox error={error} />}
      {data && (
        <>
          <Card title="Ring" right={<span className="text-mute">from the user's IdP groups and the ring order in policy</span>}>
            <div className="flex flex-wrap items-center gap-3 p-4">
              {data.ring ? <Pill tone="info" dot>{data.ring}</Pill> : <><Pill tone="bad">no ring</Pill><span className="text-mute">No ring's membership matches these groups: this user gets no tools until a ring includes one of their groups or a default ring exists.</span></>}
              {data.profile && <span className="text-mute">profile <Mono className="text-fg">{data.profile}</Mono></span>}
              {data.release && <span className="text-mute">release <Mono className="text-fg">{shortDigest(data.release)}</Mono></span>}
            </div>
          </Card>
          <Card title="Experiment variants">
            {data.assignments.length === 0 ? <Empty>No experiments defined in policy.</Empty> : data.assignments.map((a) => (
              <div key={a.experiment} className="flex items-center gap-3 border-b border-line px-4 py-2.5 last:border-0">
                <span className="font-medium">{a.experiment}</span><Pill tone={statusTone(a.status)}>{a.status || "draft"}</Pill>
                <span className="ml-auto flex items-center gap-2">{a.variant ? <><Mono>{a.variant}</Mono>{a.control && <Pill tone="info">control</Pill>}</> : <span className="text-mute">not enrolled</span>}</span>
              </div>
            ))}
          </Card>
        </>
      )}
    </div>
  );
}
