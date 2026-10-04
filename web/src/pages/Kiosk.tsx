import { useEffect, useState, type ReactNode } from "react";
import { useCatalog, useCreateRequest, useLaunch, useMe, useMyDevices, useRequests, type AccessRequest, type Host, type Launch, type Me, type MyDevices } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, ago, shortDigest, type Tone } from "../ui";

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState<string>();
  const flash = (msg: string) => {
    setDone(msg);
    setTimeout(() => setDone(undefined), 1500);
  };
  return (
    <button
      aria-live="polite"
      className="rounded-md border border-line px-2.5 py-1 text-[12px] text-mute hover:text-fg"
      onClick={() => {
        // The clipboard API is refused on plain-http origins and without permission: say so, never throw.
        (navigator.clipboard?.writeText(text) ?? Promise.reject(new Error("no clipboard"))).then(() => flash("Copied"), () => flash("Select and copy"));
      }}
    >
      {done ?? label}
    </button>
  );
}

const Code = ({ title, text }: { title: string; text: string }) => (
  <div className="rounded-md border border-line bg-panel2">
    <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-mute">
      <span>{title}</span>
      <CopyButton text={text} />
    </div>
    <pre className="overflow-x-auto p-3 font-mono text-[12px] leading-relaxed break-all whitespace-pre-wrap">{text}</pre>
  </div>
);

function Countdown({ to, onExpire }: { to: string; onExpire?: () => void }) {
  const [left, setLeft] = useState(() => Math.max(0, Math.floor((Date.parse(to) - Date.now()) / 1000)));
  useEffect(() => {
    const t = setInterval(() => setLeft(Math.max(0, Math.floor((Date.parse(to) - Date.now()) / 1000))), 1000);
    return () => clearInterval(t);
  }, [to]);
  useEffect(() => {
    if (left === 0) onExpire?.();
  }, [left, onExpire]);
  if (left === 0) return <Pill tone="bad">expired</Pill>;
  return <Pill tone={left < 60 ? "warn" : "ok"} dot>expires in {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</Pill>;
}

// One tile per launcher: what it is, and what happens after the developer uses its output.
const tiles: Record<string, { title: string; sub: string; icon: string; next: string }> = {
  devcontainer: { title: "Dev container", sub: "Add to any repo's .devcontainer", icon: "▣", next: "Save this as .devcontainer/devcontainer.json and reopen the repo in its container. The container installs your pinned CLIs and applies your ring's policy every time it starts." },
  codespaces: { title: "GitHub Codespaces", sub: "Open a ready-to-code cloud workspace", icon: "☁", next: "The workspace comes with your pinned CLIs and your ring's policy already applied." },
  coder: { title: "Coder workspace", sub: "Start a managed workspace", icon: "◈", next: "The workspace comes with your pinned CLIs and your ring's policy already applied." },
  laptop: { title: "Set up my laptop", sub: "One-time command, expires in minutes", icon: "⌘", next: "Paste this in a terminal on the machine you code on. It installs halod (a small root service that keeps your CLIs on policy), enrolls this machine and starts halod. Within a minute the machine appears under Your devices below." },
};

const SETUP_DOCS = "https://dshakes.github.io/halos/concepts/self-service-portal/";

// The aliases this harness can reach through the gateway (server-side, the check `halo validate` runs).
function HarnessModels({ models, start }: { models: string[]; start: string }) {
  if (models.length === 0) return <div className="mt-1 text-mute">Uses its vendor's models directly.</div>;
  return <div className="mt-1 flex flex-wrap gap-1">{models.map((m) => <Pill key={m} tone={m === start ? "ok" : "mute"}>{m}</Pill>)}</div>;
}

function LaunchResult({ id, r, onRegenerate }: { id: string; r: Launch; onRegenerate: () => void }) {
  return (
    <div className="space-y-3 border-t border-line p-4">
      {r.snippet && <Code title={r.filename ?? "devcontainer.json"} text={r.snippet} />}
      {r.url && /^https?:\/\//.test(r.url) && (
        <a href={r.url} target="_blank" rel="noopener noreferrer" className="inline-block rounded-md bg-accent px-4 py-2 font-medium text-white">Open workspace →</a>
      )}
      {r.token && r.expiresAt && (
        <>
          <div className="flex flex-wrap items-center gap-2"><Countdown to={r.expiresAt} /><span className="text-mute">single use</span><button className="ml-auto text-accent hover:underline" onClick={onRegenerate}>New command</button></div>
          {r.bash && <Code title="macOS / Linux" text={r.bash} />}
          {r.powershell && <Code title="Windows (PowerShell, elevated)" text={r.powershell} />}
        </>
      )}
      <p className="text-mute"><span className="font-medium text-fg">What happens next.</span> {tiles[id]?.next}</p>
    </div>
  );
}

function LauncherTile({ id, onLaunch }: { id: string; onLaunch?: () => void }) {
  const launch = useLaunch();
  const t = tiles[id] ?? { title: id, sub: "", icon: "•", next: "" };
  return (
    <Card className="overflow-hidden">
      <button onClick={() => { onLaunch?.(); launch.mutate(id); }} disabled={launch.isPending} aria-expanded={launch.data !== undefined} className="flex w-full items-center gap-3 px-4 py-4 text-left hover:bg-panel2 disabled:opacity-60">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-accent/10 text-lg text-accent" aria-hidden="true">{t.icon}</span>
        <span><span className="block font-medium">{t.title}</span><span className="text-mute">{launch.isPending ? "Preparing…" : t.sub}</span></span>
      </button>
      {launch.error && <div className="p-3"><ErrorBox error={launch.error} /></div>}
      {launch.data && <LaunchResult id={id} r={launch.data} onRegenerate={() => launch.mutate(id)} />}
    </Card>
  );
}

function RequestForm({ kind, item, onDone }: { kind: string; item: string; onDone: () => void }) {
  const [why, setWhy] = useState("");
  const create = useCreateRequest();
  return (
    <form
      className="mt-2 flex flex-wrap gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate({ kind, item, justification: why }, { onSuccess: onDone });
      }}
    >
      <input autoFocus required maxLength={1000} value={why} onChange={(e) => setWhy(e.target.value)} aria-label={`Why do you need ${item}?`} placeholder="Why do you need this?" className="h-8 min-w-0 flex-1 rounded-md border border-line bg-panel px-2.5 outline-none focus:border-accent" />
      <button disabled={create.isPending || !why.trim()} className="h-8 rounded-md bg-accent px-3 font-medium text-white disabled:opacity-50">{create.isPending ? "Sending…" : "Send"}</button>
      <button type="button" onClick={onDone} className="h-8 px-2 text-mute">Cancel</button>
      {create.error && <span role="alert" className="basis-full text-rose-600 dark:text-rose-300">{create.error.message}</span>}
    </form>
  );
}

const kindLabel: Record<string, string> = { "mcp-server": "MCP servers", model: "Models", "ring-opt-in": "Beta rings", harness: "Harnesses" };

// Items the user already asked for and that are still open: offer no second request (the API answers 409).
function usePending(user: string): Set<string> {
  const { data } = useRequests(user !== ""); // "" = self-service off: nothing to ask the API
  return new Set((data ?? []).filter((r) => r.user === user && (r.status === "pending" || r.status === "approving")).map((r) => `${r.kind}/${r.item}`));
}

function Requestable({ me }: { me: Me }) {
  const cat = useCatalog(me.selfService);
  const pending = usePending(me.id);
  const [open, setOpen] = useState<string>();
  if (cat.error) return <ErrorBox error={cat.error} />;
  if (cat.isLoading) return <Empty>Loading…</Empty>;
  const groups = new Map<string, { item: string; desc?: string }[]>();
  for (const it of cat.data?.items ?? []) groups.set(it.kind, [...(groups.get(it.kind) ?? []), it]);
  if (groups.size === 0) return <Empty>Nothing else to request right now: your profile already has everything on offer.</Empty>;
  return (
    <div>
      {[...groups].map(([kind, items]) => (
        <div key={kind} className="border-b border-line px-4 py-3 last:border-0">
          <div className="mb-2 text-[11px] tracking-wide text-mute uppercase">{kindLabel[kind] ?? kind}</div>
          <div className="grid gap-2 md:grid-cols-2">
            {items.map((it) => {
              const key = `${kind}/${it.item}`;
              return (
                <div key={key} className="rounded-md border border-line px-3 py-2">
                  <div className="flex items-center gap-2"><span className="font-medium">{it.item}</span>{it.desc && <span className="truncate text-mute">{it.desc}</span>}
                    {pending.has(key) ? <span className="ml-auto"><Pill>requested</Pill></span> : open !== key && <button onClick={() => setOpen(key)} className="ml-auto rounded-md border border-line px-2 py-0.5 text-accent hover:bg-panel2">Request</button>}
                  </div>
                  {open === key && <RequestForm kind={kind} item={it.item} onDone={() => setOpen(undefined)} />}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// What each request state means for the person waiting on it.
const requestState: Record<AccessRequest["status"], { tone: Tone; label: string; what: string }> = {
  pending: { tone: "warn", label: "waiting for an admin", what: "An admin reviews it; approving opens a policy change for a second person to merge." },
  approving: { tone: "info", label: "approved, change proposed", what: "An admin approved it. The policy change is open for review; it takes effect once merged and your machine checks in." },
  approved: { tone: "ok", label: "approved", what: "Merged. Your machine picks it up at its next check-in (within about 15 minutes)." },
  denied: { tone: "bad", label: "denied", what: "You can ask again with more context." },
};

function MyRequests({ me }: { me: Me }) {
  const { data, error, isLoading } = useRequests();
  if (error) return <ErrorBox error={error} />;
  if (isLoading) return <Empty>Loading…</Empty>;
  const mine = (data ?? []).filter((r) => r.user === me.id);
  if (mine.length === 0) return <Empty>No requests yet. Anything you ask for above shows up here with its status.</Empty>;
  return (
    <ul>
      {mine.map((r) => {
        const st = requestState[r.status];
        return (
          <li key={r.id} className="border-b border-line px-4 py-2.5 last:border-0">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <Pill tone={st.tone} dot>{st.label}</Pill>
              <span><span className="font-medium">{r.item}</span> <span className="text-mute">{kindLabel[r.kind] ?? r.kind}</span></span>
              <span className="ml-auto text-mute" title={r.createdAt}>{ago(r.createdAt)}</span>
            </div>
            <div className="mt-1 text-mute">
              {st.what}
              {r.prURL && (/^https?:\/\//.test(r.prURL) ? <> <a className="text-accent hover:underline" href={r.prURL} target="_blank" rel="noopener noreferrer">View the change →</a></> : <> Change: {r.prURL}.</>)}
              {r.note && <> Note from {r.decidedBy ?? "the admin"}: “{r.note}”</>}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// ---- your devices: the confirmation that enrollment worked and the gateway will let this machine through ----

type DeviceRow = MyDevices["devices"][number];

function deviceState(d: DeviceRow, posture: MyDevices["posture"]): { tone: Tone; label: string; hint?: string } {
  if (d.device.revoked) return { tone: "bad", label: "revoked", hint: "An admin revoked this device. Enroll again from Set up my laptop if you still use it." };
  if (d.expired) return { tone: "bad", label: "enrollment expired", hint: "Device tokens expire; run Set up my laptop again on this machine." };
  if (!d.last) return { tone: "warn", label: "waiting for first check-in", hint: "halod has not reported yet. It checks in right after enrollment; if this stays, run `sudo halod once` on the machine." };
  if (d.last.errorCode || d.last.lastError) return { tone: "bad", label: "needs attention", hint: d.last.lastError || d.last.errorCode };
  if (d.last.drift.length > 0) return { tone: "warn", label: "drifted", hint: `Managed settings were changed locally (${d.last.drift.join(", ")}). halod restores them on its next run.` };
  if (!posture.compliant && posture.reason?.includes(d.last.hostname)) return { tone: "warn", label: "not compliant", hint: posture.reason };
  return { tone: "ok", label: "compliant" };
}

function HarnessVersions({ h }: { h: Host }) {
  const rows = Object.entries(h.harnesses);
  if (rows.length === 0) return <span className="text-mute">no CLIs reported yet</span>;
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1">
      {rows.map(([n, s]) => (
        <span key={n} className="whitespace-nowrap">
          <span className="text-mute">{n} </span>
          <Mono className={s.installed === s.want ? "" : "text-amber-600 dark:text-amber-300"}>{s.installed || "installing…"}</Mono>
          {s.installed !== s.want && <span className="text-mute"> → <Mono>{s.want}</Mono></span>}
        </span>
      ))}
    </div>
  );
}

function Devices({ expecting }: { expecting: boolean }) {
  const { data, error, isLoading } = useMyDevices(expecting);
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  const live = data.devices.filter((d) => !d.device.revoked && !d.expired);
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3" data-testid="posture">
        {data.posture.compliant ? (
          <><Pill tone="ok" dot>all set</Pill><span>Your {live.length === 1 ? "device is" : "devices are"} enrolled and compliant: the model gateway accepts requests from {live.length === 1 ? "it" : "them"}.</span></>
        ) : live.length === 0 ? (
          <><Pill tone="mute" dot>no device yet</Pill><span className="text-mute">{expecting ? "Waiting for your machine to enroll and check in…" : "Pick a setup above to enroll the machine you code on."}</span></>
        ) : (
          <><Pill tone="warn" dot>not compliant</Pill><span className="text-mute">{data.posture.reason}</span></>
        )}
      </div>
      {data.devices.length === 0 ? (
        <Empty>No device enrolled yet.{expecting && " This list updates by itself once the command finishes."}</Empty>
      ) : (
        <ul>
          {data.devices.map((d) => {
            const st = deviceState(d, data.posture);
            return (
              <li key={d.device.id} className="space-y-1 border-b border-line px-4 py-3 last:border-0">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <Pill tone={st.tone} dot>{st.label}</Pill>
                  <span className="font-medium">{d.last?.hostname ?? "new device"}</span>
                  <span className="text-mute">enrolled {ago(d.device.createdAt)}{d.last && <> · checked in {ago(d.last.lastSeen)}</>}</span>
                  {d.last?.ring && <span className="text-mute md:ml-auto">ring <Mono className="text-fg">{d.last.ring}</Mono> · release <Mono className="text-fg">{shortDigest(d.last.digest)}</Mono></span>}
                </div>
                {d.last && <HarnessVersions h={d.last} />}
                {st.hint && <div className="text-mute">{st.hint}</div>}
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}

function Help({ me }: { me: Me }) {
  return (
    <dl className="grid gap-x-6 gap-y-3 p-4 md:grid-cols-[auto_1fr]">
      <dt className="font-medium">A CLI will not start, or settings look wrong</dt>
      <dd className="text-mute">Run <Mono className="text-fg">sudo halod status</Mono> on the machine. It prints the release applied, each CLI's pinned and installed version, drift and the last error. <Mono className="text-fg">sudo halod once</Mono> re-applies your ring's policy now.</dd>
      <dt className="font-medium">A request fails with “device posture check failed”</dt>
      <dd className="text-mute">The model gateway only serves machines that are enrolled, checking in, and on their ring's current release. The message names what is missing; usually halod is not running (<Mono className="text-fg">sudo halod service install --start</Mono>) or the machine was never enrolled (use Set up my laptop above). Your devices, above, shows the same verdict live.</dd>
      <dt className="font-medium">Still stuck</dt>
      <dd className="text-mute">
        {me.supportURL && /^https?:\/\//.test(me.supportURL) ? <><a className="text-accent hover:underline" href={me.supportURL} target="_blank" rel="noopener noreferrer">Contact support →</a> Include the output of <Mono className="text-fg">sudo halod status</Mono>.</> : <>Ask your platform team and include the output of <Mono className="text-fg">sudo halod status</Mono>.</>}
      </dd>
    </dl>
  );
}

const Step = ({ n, children }: { n: number; children: ReactNode }) => (
  <span className="inline-flex items-center gap-2"><span className="grid size-5 place-items-center rounded-full bg-accent text-[11px] font-semibold text-white" aria-hidden="true">{n}</span>{children}</span>
);

const Section = ({ title, children }: { title: ReactNode; children: ReactNode }) => (
  <section className="space-y-3"><h2 className="text-[13px] font-semibold">{title}</h2>{children}</section>
);

export function Kiosk() {
  const { data: me, error, isLoading } = useMe();
  const [optin, setOptin] = useState<string>();
  const [expecting, setExpecting] = useState(false); // a laptop command was generated: poll for the device fast
  const pending = usePending(me?.selfService ? me.id : "");
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !me) return <Empty>Loading…</Empty>;
  const p = me.profile;
  const harnessNames = p ? Object.keys(p.harnesses) : [];
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Hi, {me.id.split("@")[0]}</h1>
        <p className="mt-1 max-w-3xl">
          {harnessNames.length > 0 ? <>Halos sets up <span className="font-medium">{harnessNames.join(", ")}</span> for you and keeps {harnessNames.length === 1 ? "it" : "them"} that way: pinned versions, approved models and MCP servers, and settings that update themselves. Nothing to configure by hand.</> : <>Halos sets up your AI coding tools and keeps them on policy: pinned versions, approved models and MCP servers, and settings that update themselves.</>}
        </p>
        <p className="mt-1 text-mute">
          {me.ring ? <>You are in rollout ring <Mono className="text-fg">{me.ring}</Mono>{p && <> with the <Mono className="text-fg">{p.name}</Mono> profile</>}: that decides which versions and models you get, and how early you get new ones.</> : <>You are not in a rollout ring yet, so no tools are assigned to you. Ask your platform team to add your group to a ring.</>}
        </p>
      </div>

      <Section title="Your AI tools">
        {!p ? <Empty>No profile is assigned to you yet.</Empty> : (
          <div className="grid gap-3 md:grid-cols-3">
            {Object.entries(p.harnesses).map(([name, version]) => (
              <Card key={name} className="px-4 py-3.5">
                <div className="flex items-center justify-between gap-2"><span className="font-medium">{name}</span><Pill tone="info">v{version}</Pill></div>
                <div className="mt-3 text-mute">Models</div>
                <HarnessModels models={p.harnessModels[name] ?? []} start={p.harnessDefault[name] ?? p.defaultModel} />
                {p.mcpServers.length > 0 && <><div className="mt-3 text-mute">Approved MCP servers</div><div className="mt-1 flex flex-wrap gap-1">{p.mcpServers.map((m) => <Pill key={m}>{m}</Pill>)}</div></>}
              </Card>
            ))}
          </div>
        )}
      </Section>

      {me.selfService && (me.launchers.length > 0 || me.launcherSetup.length > 0) && (
        <Section title={<Step n={1}>Pick where you code</Step>}>
          <p className="text-mute">Each option gives you the tools above, already on policy. One machine or workspace is enough to start; you can add more later.</p>
          <div className="grid items-start gap-3 md:grid-cols-2">{me.launchers.map((l) => <LauncherTile key={l} id={l} onLaunch={l === "laptop" ? () => setExpecting(true) : undefined} />)}</div>
          {me.launchers.length === 0 && <Empty>No setup option is ready on this server yet.</Empty>}
          {me.launcherSetup.map((s) => (
            <p key={s.launcher} className="text-mute">
              <span className="text-fg">{tiles[s.launcher]?.title ?? s.launcher}</span> is not set up yet: the portal config needs {s.missing}.{" "}
              <a className="text-accent hover:underline" href={SETUP_DOCS} target="_blank" rel="noopener noreferrer">Setup guide</a>
              <span className="ml-1">(only admins see this)</span>
            </p>
          ))}
        </Section>
      )}

      <Section title={me.selfService ? <Step n={2}>Your devices</Step> : "Your devices"}>
        <Card><Devices expecting={expecting} /></Card>
      </Section>

      <Section title={me.selfService ? <Step n={3}>If something breaks</Step> : "If something breaks"}>
        <Card><Help me={me} /></Card>
      </Section>

      {me.optInRings.length > 0 && (
        <Section title="Try the beta">
          {me.optInRings.map((ring) => (
            <Card key={ring} className="px-4 py-4">
              <div className="flex flex-wrap items-center gap-3"><span className="grid size-9 shrink-0 place-items-center rounded-lg bg-amber-500/10 text-amber-500" aria-hidden="true">★</span>
                <div className="min-w-0 flex-1"><div className="font-medium">Join {ring}</div><div className="text-mute">Get new versions earlier. Ask for access; an admin reviews it and the change lands as a policy update.</div></div>
                {pending.has(`ring-opt-in/${ring}`) ? <Pill tone="warn" dot>requested</Pill> : optin !== ring && <button onClick={() => setOptin(ring)} className="rounded-md bg-accent px-3 py-1.5 font-medium text-white">Opt in</button>}</div>
              {optin === ring && <RequestForm kind="ring-opt-in" item={ring} onDone={() => setOptin(undefined)} />}
            </Card>
          ))}
        </Section>
      )}

      {me.selfService && (
        <>
          <Section title="Request something"><Card><Requestable me={me} /></Card></Section>
          <Section title="My requests"><Card><MyRequests me={me} /></Card></Section>
        </>
      )}
    </div>
  );
}
