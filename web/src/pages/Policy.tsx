import { useState } from "react";
import { useHarnesses, usePolicy } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill } from "../ui";

function Matrix() {
  const { data, error } = useHarnesses();
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>Loading…</Empty>;
  const names = Object.keys(data).sort();
  const caps = [...new Set(Object.values(data).flat())].sort();
  return (
    <Card title="Harness capabilities" right={<span className="text-mute">what each adapter can enforce centrally</span>}>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead className="text-[11px] tracking-wide text-mute uppercase">
            <tr className="border-b border-line"><th className="px-4 py-2 font-medium">Capability</th>{names.map((n) => <th key={n} className="px-4 py-2 text-center font-medium">{n}</th>)}</tr>
          </thead>
          <tbody>
            {caps.map((c) => (
              <tr key={c} className="border-b border-line last:border-0 hover:bg-panel2">
                <td className="px-4 py-1.5"><Mono>{c}</Mono></td>
                {names.map((n) => <td key={n} className="px-4 py-1.5 text-center">{data[n]?.includes(c) ? <span className="text-emerald-500" aria-label="supported">●</span> : <span className="text-mute" aria-label="unsupported">–</span>}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function Policy() {
  const { data, error, isLoading } = usePolicy();
  const [sel, setSel] = useState<string>();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const ring = data.rings.find((r) => r.name === sel) ?? data.rings[0];
  return (
    <div className="space-y-5">
      {data.issues.length > 0 && (
        <Card title={`Validation · ${data.issues.length}`} right={<span className="text-mute">from halo validate on the served policy</span>}>
          {data.issues.map((i, k) => (
            <div key={k} className="flex items-center gap-3 border-b border-line px-4 py-2 last:border-0">
              <Pill tone={i.severity === "error" ? "bad" : "warn"}>{i.severity}</Pill><Mono>{i.path}</Mono><span className="text-mute">{i.message}</span>
            </div>
          ))}
        </Card>
      )}
      <div className="grid gap-5 lg:grid-cols-[260px_1fr]">
        <Card title={`Rings · ${data.org}`}>
          {data.rings.map((r) => (
            <button key={r.name} onClick={() => setSel(r.name)} className={`block w-full border-b border-line px-4 py-2.5 text-left last:border-0 hover:bg-panel2 ${ring?.name === r.name ? "bg-panel2" : ""}`}>
              <div className="flex items-center justify-between"><span className="font-medium">{r.name}</span><span className="text-mute">{r.membership.default ? "default" : r.membership.percent ? `${r.membership.percent}%` : "groups"}</span></div>
              <div className="mt-0.5 text-mute">{r.profile}</div>
            </button>
          ))}
        </Card>
        {ring ? (
          <Card title={`Resolved profile · ${ring.profile}`} right={ring.release ? <Mono className="text-mute">{ring.release}</Mono> : <Pill>unpinned</Pill>}>
            {ring.membership.groups.length > 0 && <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-4 py-2.5"><span className="text-mute">groups</span>{ring.membership.groups.map((g) => <Pill key={g} tone="info">{g}</Pill>)}</div>}
            {ring.error ? <div className="p-4"><ErrorBox error={`This ring's profile does not resolve: ${ring.error}. Fix it in the policy repo and run halo validate.`} /></div> : <pre className="max-h-[60vh] overflow-auto p-4 font-mono text-[12px] leading-relaxed">{JSON.stringify(ring.resolved, null, 2)}</pre>}
          </Card>
        ) : <Empty>No rings defined in policy.</Empty>}
      </div>
      <Matrix />
    </div>
  );
}
