import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { ApiError, useMe, useRequests } from "./api";
import { Audit } from "./pages/Audit";
import { Approvals } from "./pages/Approvals";
import { Debugger } from "./pages/Debugger";
import { Device } from "./pages/Device";
import { Experiments } from "./pages/Experiments";
import { Fleet } from "./pages/Fleet";
import { Kiosk } from "./pages/Kiosk";
import { Overview } from "./pages/Overview";
import { Policy } from "./pages/Policy";
import { Releases } from "./pages/Releases";
import { Toggles } from "./pages/Toggles";
import { ErrorBox } from "./ui";

const subscribe = (cb: () => void) => {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
};
const useHash = () => useSyncExternalStore(subscribe, () => window.location.hash);

function useTheme() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("theme", dark ? "dark" : "light");
  }, [dark]);
  return [dark, () => setDark((d) => !d)] as const;
}

function Login() {
  return (
    <div className="grid h-full place-items-center">
      <div className="w-80 rounded-xl border border-line bg-panel p-8 text-center">
        <svg viewBox="0 0 16 16" className="mx-auto size-8 text-accent"><path d="M2 3h6l6 5-6 5H2l6-5z" fill="currentColor" /></svg>
        <h1 className="mt-4 text-lg font-semibold">Halos</h1>
        <p className="mt-1 text-mute">Sign in with your company account.</p>
        <a href="/auth/login" className="mt-6 block rounded-md bg-accent px-4 py-2 font-medium text-white">Continue</a>
      </div>
    </div>
  );
}

export function App() {
  const [page = "", arg] = useHash().replace(/^#\/?/, "").split("/");
  const [dark, toggle] = useTheme();
  const me = useMe();
  const admin = me.data?.admin === true;
  const reqs = useRequests(admin);
  if (me.error instanceof ApiError && me.error.status === 401) return <Login />;
  if (me.error) return <div className="p-8"><ErrorBox error={me.error} /></div>;
  if (!me.data) return null;

  const pending = (reqs.data ?? []).filter((r) => r.status === "pending").length;
  const signOut = () => { void fetch("/auth/logout", { method: "POST" }).then(() => window.location.reload()); };
  const nav: [string, string][] = admin
    ? [["", "Overview"], ["kiosk", "Kiosk"], ["fleet", "Fleet"], ["releases", "Releases"], ["experiments", "Experiments"], ["toggles", "Toggles"], ["policy", "Policy"], ["debug", "Assignment"], ["approvals", "Approvals"], ["audit", "Audit log"]]
    : [["", "Home"], ["debug", "Why this setup?"]];

  let view: ReactNode;
  switch (page) {
    case "kiosk": view = <Kiosk />; break;
    case "debug": view = <Debugger self={admin ? undefined : me.data.id} />; break;
    case "fleet": view = admin ? <Fleet /> : <Kiosk />; break;
    case "releases": view = admin ? <Releases /> : <Kiosk />; break;
    case "audit": view = admin ? <Audit /> : <Kiosk />; break;
    case "devices": view = admin && arg ? <Device id={decodeURIComponent(arg)} /> : <Kiosk />; break;
    case "experiments": view = admin ? <Experiments name={arg ? decodeURIComponent(arg) : undefined} /> : <Kiosk />; break;
    case "toggles": view = admin ? <Toggles name={arg ? decodeURIComponent(arg) : undefined} /> : <Kiosk />; break;
    case "policy": view = admin ? <Policy /> : <Kiosk />; break;
    case "approvals": view = admin ? <Approvals /> : <Kiosk />; break;
    default: view = admin ? <Overview /> : <Kiosk />;
  }
  return (
    // Phone widths stack the shell: a top bar with a scrollable nav, the page beneath. From md up the nav is a sidebar.
    <div className="grid h-full grid-rows-[auto_1fr] md:grid-cols-[200px_1fr] md:grid-rows-1">
      <aside className="flex min-w-0 flex-col gap-2 border-b border-line bg-panel px-3 py-2 md:gap-0 md:border-r md:border-b-0 md:py-4">
        <div className="flex items-center gap-2 px-2 font-semibold tracking-tight md:mb-6">
          <svg viewBox="0 0 16 16" className="size-4 text-accent" aria-hidden="true"><path d="M2 3h6l6 5-6 5H2l6-5z" fill="currentColor" /></svg>Halos
          <span className="ml-auto flex items-center gap-1 md:hidden">
            <button onClick={toggle} aria-label={`Switch to ${dark ? "light" : "dark"} theme`} className="rounded-md border border-line px-2 py-1 text-[12px] text-mute">{dark ? "Light" : "Dark"}</button>
            {!me.data.devInsecure && <button onClick={signOut} className="rounded-md border border-line px-2 py-1 text-[12px] text-mute">Sign out</button>}
          </span>
        </div>
        <nav aria-label="Main" className="-mx-3 flex gap-1 overflow-x-auto px-3 pb-1 md:mx-0 md:block md:space-y-0.5 md:overflow-visible md:px-0 md:pb-0">
          {nav.map(([p, label]) => (
            <a key={p} href={`#/${p}`} aria-current={page === p ? "page" : undefined} className={`flex shrink-0 items-center justify-between gap-2 rounded-md px-2.5 py-1.5 whitespace-nowrap ${page === p || (p === "fleet" && page === "devices") ? "bg-panel2 font-medium text-fg" : "text-mute hover:bg-panel2 hover:text-fg"}`}>
              {label}
              {p === "approvals" && pending > 0 && <span className="rounded-full bg-accent px-1.5 text-[10px] font-medium text-white" aria-label={`${pending} pending`}>{pending}</span>}
            </a>
          ))}
        </nav>
        <div className="mt-auto hidden space-y-2 md:block">
          {me.data.devInsecure && <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-600 dark:text-amber-300">Insecure demo mode: login disabled</div>}
          <div className="truncate px-1 text-mute" title={me.data.id}>{me.data.id}{admin && " · admin"}</div>
          <button onClick={toggle} className="w-full rounded-md border border-line px-2.5 py-1.5 text-left text-mute hover:text-fg">{dark ? "Light" : "Dark"} theme</button>
          {!me.data.devInsecure && <button onClick={signOut} className="w-full rounded-md border border-line px-2.5 py-1.5 text-left text-mute hover:text-fg">Sign out</button>}
        </div>
      </aside>
      <main className="min-w-0 overflow-y-auto p-4 md:p-6"><div className="mx-auto max-w-6xl">{view}</div></main>
    </div>
  );
}
