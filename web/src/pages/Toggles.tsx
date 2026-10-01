import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useMe, usePolicy, useProposeToggle, useToggle, useToggleKill, useToggles, type Toggle, type ToggleProposal, type ToggleRule } from "../api";
import { Card, Empty, ErrorBox, Mono, Modal, Pill, ago } from "../ui";

/** A rule as a sentence: "10% of ring1-canary", "group acme-platform-eng". */
export function ruleSentence(r: ToggleRule): string {
  const who: string[] = [];
  if (r.rings.length) who.push(r.rings.join(" or "));
  if (r.groups.length) who.push(`group ${r.groups.join(" or ")}`);
  if (r.users.length) who.push(`user ${r.users.join(", ")}`);
  const scope = who.join(" and ");
  const verb = r.effect === "off" ? "off for " : "";
  if (r.percent !== undefined) {
    if (r.percent === 0) return `${verb}nobody (0% rollout)`;
    return `${verb}${r.percent}% of ${scope || "everyone"}`;
  }
  return `${verb}${scope ? `members of ${scope}` : "everyone"}`;
}

type Chip = "default-on" | "killed" | "stale";
const chipLabel: Record<Chip, string> = { "default-on": "On by default", killed: "Killed", stale: "Stale" };

function stateOf(t: Toggle): { label: string; tone: "ok" | "bad" | "warn" | "mute" } {
  if (t.kill) return { label: "killed", tone: "bad" };
  if (t.stale) return { label: "stale", tone: "warn" };
  return t.default ? { label: "on by default", tone: "ok" } : { label: "targeted", tone: "mute" };
}

const input = "h-8 rounded-md border border-line bg-panel px-2.5 text-[13px] outline-none focus:border-accent";
const btn = "rounded-md border border-line px-3 py-1.5 hover:bg-panel2 disabled:opacity-50";
const csv = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[12px] text-mute">{label}</span>
      {children}
      {hint && <span className="mt-0.5 block text-[11px] text-mute">{hint}</span>}
    </label>
  );
}

/** Kill or restore: a reason dialog. A kill needs a reason; a restore may omit it. */
function KillDialog({ t, onClose }: { t: Toggle; onClose: () => void }) {
  const kill = useToggleKill();
  const [reason, setReason] = useState("");
  const killing = !t.kill;
  return (
    <Modal title={killing ? `Kill ${t.name}?` : `Restore ${t.name}?`} onClose={onClose}>
      <p className="mb-3 text-mute">
        {killing ? "It turns off for everyone at the next poll of gateways and devices, with no release and no PR. Restore it the same way." : "Its targeting rules apply again at the next poll."}
      </p>
      <Field label={killing ? "Reason (required, audit-logged)" : "Reason (optional)"}>
        <input autoFocus className={`${input} w-full`} value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
      {kill.error && <div className="mt-3"><ErrorBox error={kill.error} /></div>}
      <div className="mt-4 flex justify-end gap-2">
        <button className={btn} onClick={onClose}>Cancel</button>
        <button
          className={`rounded-md px-3 py-1.5 font-medium text-white disabled:opacity-50 ${killing ? "bg-rose-600" : "bg-accent"}`}
          disabled={kill.isPending || (killing && reason.trim() === "")}
          onClick={() => kill.mutate({ name: t.name, kill: killing, reason }, { onSuccess: onClose })}
        >
          {killing ? "Kill toggle" : "Restore toggle"}
        </button>
      </div>
    </Modal>
  );
}

/** The change form: opens a validated policy PR. */
function ProposeForm({ t }: { t: Toggle }) {
  const propose = useProposeToggle();
  const [def, setDef] = useState<"" | "on" | "off">("");
  const [rule, setRule] = useState(t.rules[0] ? (t.rules[0].name ?? "0") : "");
  const [percent, setPercent] = useState("");
  const [addRings, setAddRings] = useState("");
  const [removeRings, setRemoveRings] = useState("");
  const [addGroups, setAddGroups] = useState("");
  const [removeGroups, setRemoveGroups] = useState("");
  const [expires, setExpires] = useState("");
  const [reason, setReason] = useState("");
  const change = useMemo<ToggleProposal>(() => {
    const c: ToggleProposal = { reason: reason.trim() };
    if (def) c.default = def === "on";
    if (expires) c.expires = expires;
    const ruleEdit = percent !== "" || [addRings, removeRings, addGroups, removeGroups].some((x) => csv(x).length);
    if (ruleEdit) {
      c.rule = rule;
      if (percent !== "") c.percent = Number(percent);
      if (csv(addRings).length) c.addRings = csv(addRings);
      if (csv(removeRings).length) c.removeRings = csv(removeRings);
      if (csv(addGroups).length) c.addGroups = csv(addGroups);
      if (csv(removeGroups).length) c.removeGroups = csv(removeGroups);
    }
    return c;
  }, [def, rule, percent, addRings, removeRings, addGroups, removeGroups, expires, reason]);
  const changed = Object.keys(change).some((k) => k !== "reason");
  return (
    <form
      className="space-y-3 p-4"
      onSubmit={(e) => { e.preventDefault(); propose.mutate({ name: t.name, change }); }}
    >
      <div className="grid grid-cols-2 gap-3">
        <Field label="Default state">
          <select className={`${input} w-full`} value={def} onChange={(e) => setDef(e.target.value as "" | "on" | "off")}>
            <option value="">No change ({t.default ? "on" : "off"})</option>
            <option value="on">On</option>
            <option value="off">Off</option>
          </select>
        </Field>
        <Field label="Expires">
          <input type="date" className={`${input} w-full`} value={expires} onChange={(e) => setExpires(e.target.value)} />
        </Field>
      </div>
      {t.rules.length > 0 && (
        <div className="space-y-3 rounded-md border border-line p-3">
          <Field label="Rule to edit">
            <select className={`${input} w-full`} value={rule} onChange={(e) => setRule(e.target.value)}>
              {t.rules.map((r, i) => <option key={i} value={r.name ?? String(i)}>{r.name ?? `#${i}`}: {ruleSentence(r)}</option>)}
            </select>
          </Field>
          <Field label="Rollout percent" hint="0 matches nobody (ramp down); leave empty to keep it">
            <input type="number" aria-label="Rollout percent" min={0} max={100} step="any" className={`${input} w-28`} value={percent} onChange={(e) => setPercent(e.target.value)} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Add rings"><input className={`${input} w-full`} placeholder="ring1-canary, …" value={addRings} onChange={(e) => setAddRings(e.target.value)} /></Field>
            <Field label="Remove rings"><input className={`${input} w-full`} value={removeRings} onChange={(e) => setRemoveRings(e.target.value)} /></Field>
            <Field label="Add groups"><input className={`${input} w-full`} placeholder="idp-group, …" value={addGroups} onChange={(e) => setAddGroups(e.target.value)} /></Field>
            <Field label="Remove groups"><input className={`${input} w-full`} value={removeGroups} onChange={(e) => setRemoveGroups(e.target.value)} /></Field>
          </div>
        </div>
      )}
      <Field label="Reason (required; goes in the PR)">
        <input aria-label="Proposal reason" className={`${input} w-full`} required value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
      <div className="flex items-center gap-3">
        <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-white disabled:opacity-50" disabled={propose.isPending || !changed || reason.trim() === ""}>Open PR</button>
        <span className="text-mute">validated against the guardrails first; a human merges it</span>
      </div>
      {propose.error && <ErrorBox error={propose.error} />}
      {propose.data && (
        <div role="status" className="text-mute">
          PR opened: {/^https?:\/\//.test(propose.data.prURL) ? <a className="text-accent underline" href={propose.data.prURL} target="_blank" rel="noreferrer">{propose.data.prURL}</a> : propose.data.prURL}
        </div>
      )}
    </form>
  );
}

/** "Who gets it?": evaluates the toggle for a user with the server's own rule evaluator. */
function Tester({ name }: { name: string }) {
  const policy = usePolicy();
  const [user, setUser] = useState("");
  const [ring, setRing] = useState("");
  const [groups, setGroups] = useState("");
  const [asked, setAsked] = useState({ user: "", ring: "", groups: "" });
  const d = useToggle(name, asked.user, asked.ring, asked.groups);
  const p = d.data?.preview;
  return (
    <Card title="Who gets it?">
      <form className="flex flex-wrap items-end gap-2 p-4" onSubmit={(e) => { e.preventDefault(); setAsked({ user: user.trim(), ring, groups }); }}>
        <Field label="User"><input className={`${input} w-48`} placeholder="dana@acme.com" value={user} onChange={(e) => setUser(e.target.value)} /></Field>
        <Field label="Ring">
          <select className={input} value={ring} onChange={(e) => setRing(e.target.value)}>
            <option value="">resolve from user</option>
            {(policy.data?.rings ?? []).map((r) => <option key={r.name} value={r.name}>{r.name}</option>)}
          </select>
        </Field>
        <Field label="Groups"><input className={`${input} w-48`} placeholder="a, b" value={groups} onChange={(e) => setGroups(e.target.value)} /></Field>
        <button className={btn} type="submit" disabled={user.trim() === ""}>Check</button>
      </form>
      {d.error && <div className="px-4 pb-4"><ErrorBox error={d.error} /></div>}
      {p && (
        <div className="border-t border-line p-4" aria-live="polite">
          <div className="flex items-center gap-2">
            <Pill tone={p.decision.on ? "ok" : p.decision.killed ? "bad" : "mute"} dot>{p.decision.on ? "ON" : "OFF"}</Pill>
            <span>{p.decision.why}</span>
            <span className="ml-auto text-mute">ring {p.subject.ring || "—"}</span>
          </div>
          <ol className="mt-3 space-y-1">
            {p.decision.trace.map((l, i) => <li key={i}><Mono className="text-mute">{l}</Mono></li>)}
          </ol>
        </div>
      )}
    </Card>
  );
}

function Payload({ t }: { t: Toggle }) {
  const hs = Object.entries(t.payload.harnesses ?? {});
  const routes = Object.entries(t.payload.routes ?? {});
  if (hs.length === 0 && routes.length === 0) return <Empty>No payload.</Empty>;
  return (
    <div className="space-y-3 p-4">
      {hs.map(([h, p]) => (
        <div key={h}>
          <div className="mb-1 font-medium">{h}</div>
          <ul className="space-y-0.5 text-mute">
            {p.mcpServers.map((m) => <li key={m}>MCP server <Mono className="text-fg">{m}</Mono></li>)}
            {p.hooks.map((x) => <li key={x}>hook <Mono className="text-fg">{x}</Mono></li>)}
            {p.env.map((x) => <li key={x}>env <Mono className="text-fg">{x}</Mono> (value hidden)</li>)}
            {p.overrides.map((x) => <li key={x}>setting <Mono className="text-fg">{x}</Mono></li>)}
          </ul>
        </div>
      ))}
      {routes.map(([a, r]) => <div key={a}>alias <Mono>{a}</Mono> → <Mono className="text-fg">{r}</Mono></div>)}
    </div>
  );
}

function Drawer({ name, onClose }: { name: string; onClose: () => void }) {
  const d = useToggle(name, "", "", "");
  const [dialog, setDialog] = useState(false);
  const [propose, setPropose] = useState(false);
  const list = useToggles();
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape" && !dialog) onClose(); };
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [onClose, dialog]);
  const t = d.data?.toggle;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/30" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <aside role="dialog" aria-label={`Toggle ${name}`} className="h-full w-full max-w-2xl space-y-5 overflow-y-auto border-l border-line bg-bg p-6 shadow-xl">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-lg font-semibold">{name}</h2>
            {t?.description && <p className="mt-0.5 text-mute">{t.description}</p>}
          </div>
          <button className={btn} onClick={onClose} aria-label="Close">Close</button>
        </div>
        {d.error && <ErrorBox error={d.error} />}
        {!t ? (d.isLoading && <Empty>Loading…</Empty>) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Pill tone={stateOf(t).tone} dot>{stateOf(t).label}</Pill>
              <Pill>{t.axis}</Pill>
              <span className="text-mute">owner {t.owner}</span>
              {t.expires && <span className={t.stale ? "text-amber-600 dark:text-amber-300" : "text-mute"}>{t.stale ? "expired" : "expires"} {t.expires}</span>}
            </div>

            {t.kill && (
              <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-rose-700 dark:text-rose-300">
                Killed by {t.kill.by} <span title={t.kill.at}>{ago(t.kill.at)}</span>: {t.kill.reason || "no reason given"}. It is off for everyone until restored.
              </div>
            )}

            <Card title="Actions" right={<span className="ml-4 text-right text-mute">kill takes effect at the next poll (~10 s gateways, ~60 s devices); rule changes go through a PR</span>}>
              <div className="flex flex-wrap gap-2 p-4">
                {list.data?.killEnabled && (
                  <button className={t.kill ? btn : "rounded-md bg-rose-600 px-3 py-1.5 font-medium text-white"} onClick={() => setDialog(true)}>{t.kill ? "Restore" : "Kill"}</button>
                )}
                <button className={btn} onClick={() => setPropose((v) => !v)} aria-expanded={propose}>Propose change</button>
                {list.data && !list.data.killEnabled && <span className="self-center text-mute">kill switch is not configured on this server</span>}
              </div>
              {propose && <div className="border-t border-line"><ProposeForm t={t} /></div>}
            </Card>

            <Card title="Targeting" right={<span className="text-mute">first matching rule decides; default {t.default ? "on" : "off"}</span>}>
              {t.rules.length === 0 ? <Empty>No rules: the default applies to everyone.</Empty> : (
                <ol>
                  {t.rules.map((r, i) => (
                    <li key={i} className="flex items-baseline gap-3 border-b border-line px-4 py-2.5 last:border-0">
                      <span className="w-5 text-mute tabular-nums">{i + 1}</span>
                      <div>
                        <div className="font-medium">{ruleSentence(r)}</div>
                        {r.name && <Mono className="text-mute">{r.name}</Mono>}
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </Card>

            <Card title="Delivers"><Payload t={t} /></Card>
            <Tester name={name} />

            <Card title="History" right={<span className="text-mute">from the audit log</span>}>
              {d.data && d.data.history.length === 0 ? <Empty>No kills or proposals yet.</Empty> : [...(d.data?.history ?? [])].reverse().map((h) => (
                <div key={h.seq} className="flex items-baseline gap-3 border-b border-line px-4 py-2 last:border-0">
                  <Mono className="w-28 shrink-0">{h.action.replace("toggle.", "")}</Mono>
                  <div className="min-w-0 flex-1 truncate" title={h.details.reason}>{h.details.reason || h.details.change || "—"} · by {h.actor}</div>
                  <span className="text-mute" title={h.time}>{ago(h.time)}</span>
                </div>
              ))}
            </Card>
          </>
        )}
      </aside>
      {dialog && t && <KillDialog t={t} onClose={() => setDialog(false)} />}
    </div>
  );
}

export function Toggles({ name }: { name?: string }) {
  const { data, error, isLoading } = useToggles();
  const me = useMe();
  const [q, setQ] = useState("");
  const [axis, setAxis] = useState<"" | "client" | "traffic">("");
  const [chips, setChips] = useState<Chip[]>([]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.toggles ?? []).filter((t) =>
      (!needle || [t.name, t.description ?? "", t.owner].some((s) => s.toLowerCase().includes(needle))) &&
      (!axis || t.axis === axis) &&
      chips.every((c) => (c === "killed" ? !!t.kill : c === "stale" ? t.stale : t.default)),
    );
  }, [data, q, axis, chips]);
  if (me.data && !me.data.admin) return <Empty>Toggles are managed by admins.</Empty>;
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const close = () => { window.location.hash = "#/toggles"; };
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">Feature toggles</h1>
        <span className="text-mute">{data.toggles.length} total · {data.toggles.filter((t) => t.kill).length} killed · {data.toggles.filter((t) => t.stale).length} stale</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <input className={`${input} w-64`} placeholder="Search name, owner, description" aria-label="Search toggles" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="flex gap-1" role="group" aria-label="Axis">
          {([["", "All"], ["client", "Client"], ["traffic", "Traffic"]] as const).map(([v, l]) => (
            <button key={v} aria-pressed={axis === v} onClick={() => setAxis(v)} className={`rounded-md border px-2.5 py-1 ${axis === v ? "border-accent bg-panel2 font-medium" : "border-line text-mute hover:text-fg"}`}>{l}</button>
          ))}
        </div>
        <div className="flex gap-1" role="group" aria-label="Status">
          {(Object.keys(chipLabel) as Chip[]).map((c) => (
            <button key={c} aria-pressed={chips.includes(c)} onClick={() => setChips((cs) => (cs.includes(c) ? cs.filter((x) => x !== c) : [...cs, c]))} className={`rounded-full border px-2.5 py-1 ${chips.includes(c) ? "border-accent bg-panel2 font-medium" : "border-line text-mute hover:text-fg"}`}>{chipLabel[c]}</button>
          ))}
        </div>
      </div>
      <Card>
        {rows.length === 0 ? <Empty>{data.toggles.length === 0 ? "No toggles in the policy repo." : "No toggles match."}</Empty> : rows.map((t) => {
          const s = stateOf(t);
          return (
            <a key={t.name} href={`#/toggles/${encodeURIComponent(t.name)}`} className="grid grid-cols-[minmax(0,1.2fr)_minmax(0,2fr)_auto] items-center gap-4 border-b border-line px-4 py-3 last:border-0 hover:bg-panel2">
              <div className="min-w-0">
                <div className="truncate font-medium">{t.name}</div>
                <div className="truncate text-mute">{t.owner}{t.expires && <> · {t.stale ? "expired" : "expires"} {t.expires}</>}</div>
              </div>
              <div className="min-w-0 text-mute">
                <div className="truncate">{t.rules.length ? t.rules.map(ruleSentence).join("; ") : "everyone gets the default"}</div>
                {t.description && <div className="truncate text-[12px]">{t.description}</div>}
              </div>
              <div className="flex items-center gap-2"><Pill>{t.axis}</Pill><Pill tone={s.tone} dot>{s.label}</Pill></div>
            </a>
          );
        })}
      </Card>
      {name && <Drawer key={name} name={name} onClose={close} />}
    </div>
  );
}
