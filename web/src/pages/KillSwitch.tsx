import { useCapabilities, useKills, useUnkillExperiment } from "../api";
import { Card, Empty, ErrorBox, Mono, ago } from "../ui";

/** Active kills (admin). Renders nothing unless the server reports the kill switch capability. */
export function KillSwitchPanel() {
  const caps = useCapabilities();
  const enabled = caps.data?.killSwitch === true;
  const kills = useKills(enabled);
  const unkill = useUnkillExperiment();
  if (!enabled) return null;
  const active = (kills.data?.killed ?? []).filter((k) => k.killed);
  return (
    <Card title="Kill switch" right={<span className="text-mute">killed experiments fall back to control at the next gateway poll</span>}>
      {kills.error ? <ErrorBox error={kills.error} /> : kills.isLoading ? <Empty>Loading…</Empty> : active.length === 0 ? <Empty>No active kills.</Empty> : active.map((k) => (
        <div key={k.experiment} className="flex items-center gap-4 border-b border-line px-4 py-2.5 last:border-0">
          <div className="min-w-0 flex-1">
            <Mono>{k.experiment}</Mono>
            <div className="truncate text-mute" title={k.reason}>{k.reason || "no reason given"} · by {k.by} · <span title={k.at}>{ago(k.at)}</span></div>
          </div>
          <button
            className="rounded-md border border-line px-3 py-1.5 hover:bg-panel2 disabled:opacity-50"
            disabled={unkill.isPending}
            onClick={() => {
              // Optional reason (audit trail); Cancel aborts.
              const reason = window.prompt(`Unkill ${k.experiment}? Users return to their assigned variants.\nReason (optional):`, "");
              if (reason !== null) unkill.mutate({ name: k.experiment, reason });
            }}
          >
            Unkill
          </button>
        </div>
      ))}
      {unkill.error && <div className="p-4"><ErrorBox error={unkill.error} /></div>}
    </Card>
  );
}
