import { useEffect, useState, type ReactNode } from "react";
import { useCatalog, useCreateRequest, useLaunch, useMe, useRequests, type Launch, type Me } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, statusTone, ago } from "../ui";

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="rounded-md border border-line px-2.5 py-1 text-[12px] text-mute hover:text-fg"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}

const Code = ({ title, text }: { title: string; text: string }) => (
  <div className="rounded-md border border-line bg-panel2">
    <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-mute">
      <span>{title}</span>
      <CopyButton text={text} />
    </div>
    <pre className="overflow-x-auto p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-all">{text}</pre>
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

const tiles: Record<string, { title: string; sub: string; icon: string }> = {
  devcontainer: { title: "Dev container", sub: "Add to any repo's .devcontainer", icon: "▣" },
  codespaces: { title: "GitHub Codespaces", sub: "Open a ready-to-code cloud workspace", icon: "☁" },
  coder: { title: "Coder workspace", sub: "Start a managed workspace", icon: "◈" },
  laptop: { title: "Set up my laptop", sub: "One-time command, expires quickly", icon: "⌘" },
};

const SETUP_DOCS = "https://dshakes.github.io/halos/concepts/self-service-portal/";

// The aliases this harness can reach through the gateway (server-side, the check `halo validate` runs).
function HarnessModels({ models, start }: { models: string[]; start: string }) {
  if (models.length === 0) return <div className="mt-1 text-mute">Uses its vendor's models directly.</div>;
  return <div className="mt-1 flex flex-wrap gap-1">{models.map((m) => <Pill key={m} tone={m === start ? "ok" : "mute"}>{m}</Pill>)}</div>;
}

function LaunchResult({ r, onRegenerate }: { r: Launch; onRegenerate: () => void }) {
  return (
    <div className="space-y-3 border-t border-line p-4">
      {r.snippet && <Code title={r.filename ?? "devcontainer.json"} text={r.snippet} />}
      {r.url && /^https?:\/\//.test(r.url) && (
        <a href={r.url} target="_blank" rel="noopener noreferrer" className="inline-block rounded-md bg-accent px-4 py-2 font-medium text-white">Open workspace →</a>
      )}
      {r.token && r.expiresAt && (
        <>
          <div className="flex items-center gap-2"><Countdown to={r.expiresAt} /><span className="text-mute">single use</span><button className="ml-auto text-accent hover:underline" onClick={onRegenerate}>New command</button></div>
          {r.bash && <Code title="macOS / Linux" text={r.bash} />}
          {r.powershell && <Code title="Windows (PowerShell, elevated)" text={r.powershell} />}
        </>
      )}
    </div>
  );
}

function LauncherTile({ id }: { id: string }) {
  const launch = useLaunch();
  const t = tiles[id] ?? { title: id, sub: "", icon: "•" };
  return (
    <Card className="overflow-hidden">
      <button onClick={() => launch.mutate(id)} disabled={launch.isPending} className="flex w-full items-center gap-3 px-4 py-4 text-left hover:bg-panel2 disabled:opacity-60">
        <span className="grid size-9 place-items-center rounded-lg bg-accent/10 text-lg text-accent">{t.icon}</span>
        <span><span className="block font-medium">{t.title}</span><span className="text-mute">{t.sub}</span></span>
      </button>
      {launch.error && <div className="p-3"><ErrorBox error={launch.error} /></div>}
      {launch.data && <LaunchResult r={launch.data} onRegenerate={() => launch.mutate(id)} />}
    </Card>
  );
}

function RequestForm({ kind, item, onDone }: { kind: string; item: string; onDone: () => void }) {
  const [why, setWhy] = useState("");
  const create = useCreateRequest();
  return (
    <form
      className="mt-2 flex gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate({ kind, item, justification: why }, { onSuccess: onDone });
      }}
    >
      <input autoFocus required maxLength={1000} value={why} onChange={(e) => setWhy(e.target.value)} placeholder="Why do you need this?" className="h-8 min-w-0 flex-1 rounded-md border border-line bg-panel px-2.5 outline-none focus:border-accent" />
      <button disabled={create.isPending || !why.trim()} className="h-8 rounded-md bg-accent px-3 font-medium text-white disabled:opacity-50">Send</button>
      <button type="button" onClick={onDone} className="h-8 px-2 text-mute">Cancel</button>
      {create.error && <span className="self-center text-rose-500">{create.error.message}</span>}
    </form>
  );
}

const kindLabel: Record<string, string> = { "mcp-server": "MCP servers", model: "Models", "ring-opt-in": "Beta rings", harness: "Harnesses" };

function Requestable({ me }: { me: Me }) {
  const cat = useCatalog(me.selfService);
  const [open, setOpen] = useState<string>();
  if (cat.error) return <ErrorBox error={cat.error} />;
  const groups = new Map<string, { item: string; desc?: string }[]>();
  for (const it of cat.data?.items ?? []) groups.set(it.kind, [...(groups.get(it.kind) ?? []), it]);
  if (groups.size === 0) return <Empty>Nothing else to request right now.</Empty>;
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
                    {open !== key && <button onClick={() => setOpen(key)} className="ml-auto rounded-md border border-line px-2 py-0.5 text-accent hover:bg-panel2">Request</button>}
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

function MyRequests({ me }: { me: Me }) {
  const { data, error } = useRequests();
  if (error) return <ErrorBox error={error} />;
  const mine = (data ?? []).filter((r) => r.user === me.id);
  if (mine.length === 0) return <Empty>No requests yet.</Empty>;
  return (
    <ul>
      {mine.map((r) => (
        <li key={r.id} className="flex items-center gap-3 border-b border-line px-4 py-2.5 last:border-0">
          <Pill tone={statusTone(r.status === "approved" ? "pass" : r.status === "denied" ? "fail" : "paused")} dot>{r.status}</Pill>
          <span><span className="font-medium">{r.item}</span> <span className="text-mute">{r.kind}</span></span>
          <span className="ml-auto text-mute">{r.prURL && /^https?:\/\//.test(r.prURL) ? <a className="text-accent hover:underline" href={r.prURL} target="_blank" rel="noopener noreferrer">change proposed</a> : r.note ?? ""} · {ago(r.createdAt)}</span>
        </li>
      ))}
    </ul>
  );
}

export function Kiosk() {
  const { data: me, error, isLoading } = useMe();
  const [optin, setOptin] = useState<string>();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !me) return <Empty>Loading…</Empty>;
  const p = me.profile;
  const Section = ({ title, children }: { title: string; children: ReactNode }) => (
    <section className="space-y-3"><h2 className="text-[13px] font-semibold">{title}</h2>{children}</section>
  );
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Hi, {me.id.split("@")[0]}</h1>
        <p className="mt-1 text-mute">You are on ring <Mono className="text-fg">{me.ring || "none"}</Mono>{p && <> using profile <Mono className="text-fg">{p.name}</Mono></>}.</p>
      </div>

      <Section title="Your AI tools">
        {!p ? <Empty>No profile is assigned to you yet.</Empty> : (
          <div className="grid gap-3 md:grid-cols-3">
            {Object.entries(p.harnesses).map(([name, version]) => (
              <Card key={name} className="px-4 py-3.5">
                <div className="flex items-center justify-between"><span className="font-medium">{name}</span><Pill tone="info">v{version}</Pill></div>
                <div className="mt-3 text-mute">Models</div>
                <HarnessModels models={p.harnessModels[name] ?? []} start={p.harnessDefault[name] ?? p.defaultModel} />
                {p.mcpServers.length > 0 && <><div className="mt-3 text-mute">Approved MCP servers</div><div className="mt-1 flex flex-wrap gap-1">{p.mcpServers.map((m) => <Pill key={m}>{m}</Pill>)}</div></>}
              </Card>
            ))}
          </div>
        )}
      </Section>

      {me.selfService && (me.launchers.length > 0 || me.launcherSetup.length > 0) && (
        <Section title="Get started">
          <div className="grid items-start gap-3 md:grid-cols-2">{me.launchers.map((l) => <LauncherTile key={l} id={l} />)}</div>
          {me.launcherSetup.map((s) => (
            <p key={s.launcher} className="text-mute">
              <span className="text-fg">{tiles[s.launcher]?.title ?? s.launcher}</span> is not set up yet: the portal config needs {s.missing}.{" "}
              <a className="text-accent hover:underline" href={SETUP_DOCS} target="_blank" rel="noopener noreferrer">Setup guide</a>
              <span className="ml-1">(only admins see this)</span>
            </p>
          ))}
        </Section>
      )}

      {me.optInRings.length > 0 && (
        <Section title="Try the beta">
          {me.optInRings.map((ring) => (
            <Card key={ring} className="px-4 py-4">
              <div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-lg bg-amber-500/10 text-amber-500">★</span>
                <div><div className="font-medium">Join {ring}</div><div className="text-mute">Get new versions earlier. Ask for access; an admin reviews it.</div></div>
                {optin !== ring && <button onClick={() => setOptin(ring)} className="ml-auto rounded-md bg-accent px-3 py-1.5 font-medium text-white">Opt in</button>}</div>
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
