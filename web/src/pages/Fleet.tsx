import { useMemo, useState } from "react";
import { useFleet } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, StackBar, ago, colorFor, shortDigest } from "../ui";

// Human explanations for halod Status.ErrorCode values; unknown codes show the raw code.
const errorCodes: Record<string, string> = {
  untrusted_owner: "A managed or halod directory is owned by a non-admin user (possibly squatted). halod refused to write to it; remove it and let halod recreate it.",
  sandbox_unavailable: "The profile requires the Claude sandbox, but bubblewrap/socat are not installed. Claude will refuse to start until they are.",
};

const inputCls = "h-8 rounded-md border border-line bg-panel px-2.5 text-[13px] outline-none focus:border-accent";

export function Fleet() {
  const { data, error, isLoading } = useFleet();
  const [q, setQ] = useState("");
  const [ring, setRing] = useState("");
  const [harness, setHarness] = useState("");
  const [version, setVersion] = useState("");
  const [driftOnly, setDriftOnly] = useState(false);
  const [compliantOnly, setCompliantOnly] = useState(false);

  const harnessNames = useMemo(() => [...new Set((data?.hosts ?? []).flatMap((h) => Object.keys(h.harnesses)))].sort(), [data]);
  const rows = useMemo(
    () =>
      (data?.hosts ?? []).filter((h) => {
        if (ring && h.ring !== ring) return false;
        if (driftOnly && h.drift.length === 0) return false;
        if (compliantOnly && h.drift.length > 0) return false;
        if (q && !`${h.hostname} ${h.user}`.toLowerCase().includes(q.toLowerCase())) return false;
        if (version || harness) {
          const hs = Object.entries(h.harnesses).filter(([n]) => !harness || n === harness);
          if (!hs.some(([, s]) => !version || s.installed.includes(version))) return false;
        }
        return true;
      }),
    [data, q, ring, harness, version, driftOnly, compliantOnly],
  );
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const now = Date.now();

  return (
    <div className="space-y-5">
      <Card title="Version distribution" right={<span className="text-mute">installed version per ring</span>}>
        <div className="grid gap-x-8 gap-y-5 p-4 md:grid-cols-2">
          {harnessNames.map((h) => {
            const versions = [...new Set(data.rings.flatMap((r) => Object.keys(r.versions[h] ?? {})))].sort();
            return (
              <div key={h}>
                <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-medium">{h}</span>
                  {versions.map((v, i) => (
                    <span key={v} className="flex items-center gap-1 text-mute"><span className="size-2 rounded-sm" style={{ background: colorFor(i) }} /><Mono>{v || "?"}</Mono></span>
                  ))}
                </div>
                <div className="space-y-1.5">
                  {data.rings.filter((r) => r.versions[h]).map((r) => (
                    <div key={r.ring} className="grid grid-cols-[130px_1fr_32px] items-center gap-3">
                      <span className="truncate text-mute">{r.ring}</span>
                      <StackBar parts={versions.map((v) => ({ label: v, n: r.versions[h]?.[v] ?? 0 }))} />
                      <span className="text-right tabular-nums text-mute">{Object.values(r.versions[h] ?? {}).reduce((a, b) => a + b, 0)}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
          {harnessNames.length === 0 && <Empty>No device has reported yet. Developers enroll from the <a className="text-accent hover:underline" href="#/kiosk">Kiosk</a>; by hand on a machine: <Mono>sudo halod once</Mono>.</Empty>}
        </div>
      </Card>

      <Card title="Compliance" right={<span className="text-mute">devices with no drift, per ring</span>}>
        {data.total === 0 ? <Empty>No device has reported yet.</Empty> : (
          <div className="space-y-1.5 p-4">
            {[{ ring: "All rings", hosts: data.total, driftHosts: data.driftHosts }, ...data.rings].map((r) => {
              const pct = r.hosts ? (100 * (r.hosts - r.driftHosts)) / r.hosts : 100;
              return (
                <div key={r.ring} className="grid grid-cols-[130px_1fr_150px] items-center gap-3">
                  <span className="truncate text-mute">{r.ring || "(none)"}</span>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-panel2" role="meter" aria-label={`${r.ring || "no ring"} compliance`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(pct)}><div className={`h-2 ${r.driftHosts > 0 ? "bg-amber-500" : "bg-emerald-500"}`} style={{ width: `${pct}%` }} /></div>
                  <span className="text-right tabular-nums"><span className={r.driftHosts > 0 ? "text-amber-600 dark:text-amber-300" : ""}>{pct.toFixed(0)}%</span> <span className="text-mute">{r.driftHosts} of {r.hosts} drifted</span></span>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Card
        title={`Devices · ${rows.length}/${data.total}${data.total ? ` · ${Math.round((100 * (data.total - data.driftHosts)) / data.total)}% in sync` : ""}`}
        right={
          <div className="flex flex-wrap items-center gap-2">
            <input className={`${inputCls} w-44`} placeholder="Search host or user" aria-label="Search host or user" value={q} onChange={(e) => setQ(e.target.value)} />
            <select className={inputCls} value={ring} onChange={(e) => setRing(e.target.value)} aria-label="Ring">
              <option value="">All rings</option>
              {data.rings.map((r) => <option key={r.ring}>{r.ring}</option>)}
            </select>
            <select className={inputCls} value={harness} onChange={(e) => setHarness(e.target.value)} aria-label="Harness">
              <option value="">All harnesses</option>
              {harnessNames.map((h) => <option key={h}>{h}</option>)}
            </select>
            <input className={`${inputCls} w-28`} placeholder="Version" aria-label="Installed version contains" value={version} onChange={(e) => setVersion(e.target.value)} />
            <label className="flex items-center gap-1.5 text-mute"><input type="checkbox" checked={driftOnly} onChange={(e) => { setDriftOnly(e.target.checked); if (e.target.checked) setCompliantOnly(false); }} />Drift</label>
            <label className="flex items-center gap-1.5 text-mute"><input type="checkbox" checked={compliantOnly} onChange={(e) => { setCompliantOnly(e.target.checked); if (e.target.checked) setDriftOnly(false); }} />In sync</label>
          </div>
        }
      >
        <div className="overflow-x-auto">
        <table className="w-full text-left">
          <caption className="sr-only">Enrolled devices and their last report</caption>
          <thead className="text-[11px] tracking-wide text-mute uppercase">
            <tr className="border-b border-line">
              {["Host", "Ring", "Release", "Harnesses", "Drift", "Last seen"].map((c) => <th key={c} scope="col" className="px-4 py-2 font-medium">{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => {
              const stale = now - Date.parse(h.lastSeen) > 24 * 3600 * 1000;
              return (
                <tr key={h.device ?? h.hostname} className={`border-b border-line last:border-0 hover:bg-panel2 ${h.device ? "cursor-pointer" : ""}`} onClick={h.device ? () => { window.location.hash = `#/devices/${encodeURIComponent(h.device ?? "")}`; } : undefined}>
                  <td className="px-4 py-2"><div className="font-medium">{h.device ? <a className="text-accent hover:underline" href={`#/devices/${encodeURIComponent(h.device)}`} aria-label={`Device details for ${h.hostname}`}>{h.hostname}</a> : h.hostname}</div><div className="text-mute">{h.user}</div></td>
                  <td className="px-4 py-2"><Pill tone="info">{h.ring || "—"}</Pill></td>
                  <td className="px-4 py-2"><Mono>{shortDigest(h.digest)}</Mono></td>
                  <td className="px-4 py-2">
                    {Object.entries(h.harnesses).map(([n, s]) => (
                      <div key={n} className="flex items-center gap-2">
                        <span className="w-24 text-mute">{n}</span>
                        <Mono className={s.installed === s.want ? "" : "text-amber-500"}>{s.installed || "missing"}</Mono>
                        {s.installed !== s.want && <span className="text-mute">→ <Mono>{s.want}</Mono></span>}
                      </div>
                    ))}
                  </td>
                  <td className="px-4 py-2">
                    {h.drift.length ? <div className="flex flex-wrap items-center gap-1"><Pill tone="warn" dot>{h.drift.length} drifted</Pill>{h.drift.map((d) => <Pill key={d} tone="warn">{d}</Pill>)}</div> : <Pill tone="ok" dot>in sync</Pill>}
                    {h.errorCode && (
                      <div className="mt-1 max-w-64" title={errorCodes[h.errorCode] ?? h.errorCode}>
                        <Pill tone="bad">{h.errorCode}</Pill>
                        <div className="mt-1 text-mute">{errorCodes[h.errorCode] ?? "Unrecognised error code."}</div>
                      </div>
                    )}
                    {h.lastError && <div className="mt-1 max-w-64 truncate text-rose-500" title={h.lastError}>{h.lastError}</div>}
                  </td>
                  <td className={`px-4 py-2 whitespace-nowrap ${stale ? "text-amber-600 dark:text-amber-300" : "text-mute"}`} title={stale ? "No report for over a day: is halod running?" : h.lastSeen}>{ago(h.lastSeen, now)}{stale && " · stale"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
        {rows.length === 0 && <Empty>{data.total === 0 ? "No device has reported yet." : "No device matches these filters."}</Empty>}
      </Card>
    </div>
  );
}
