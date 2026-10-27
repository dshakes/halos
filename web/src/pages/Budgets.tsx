import { useBudgets, type BudgetStatus } from "../api";
import { Card, Empty, ErrorBox, Mono, Pill, type Tone } from "../ui";

const scopes = ["org", "ring", "group", "user"] as const;
const usd = (n: number) => `$${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const num = (n: number) => n.toLocaleString();

/** Larger of spent/limit over USD and tokens; mirrors budget.Status.Utilization (0 when unlimited). */
export function utilization(b: BudgetStatus): number {
  return Math.max(b.limitUSD ? b.spentUSD / b.limitUSD : 0, b.limitTokens ? b.spentTokens / b.limitTokens : 0);
}

function Bar({ b }: { b: BudgetStatus }) {
  const u = utilization(b);
  const alert = Math.min(...(b.alertAt.length ? b.alertAt : [0.8]));
  const tone: Tone = u >= 1 ? "bad" : u >= alert ? "warn" : "ok";
  const fill = { ok: "bg-emerald-500", warn: "bg-amber-500", bad: "bg-rose-500", info: "bg-indigo-500", mute: "bg-zinc-500" }[tone];
  return (
    <div className="min-w-40">
      <div className="relative h-2 w-full rounded-full bg-panel2" role="meter" aria-label={`${b.budget} ${b.key} utilization`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.min(100, Math.round(u * 100))}>
        <div className={`h-2 rounded-full ${fill}`} style={{ width: `${Math.min(100, u * 100)}%` }} />
        {b.alertAt.map((a) => <div key={a} title={`alert at ${Math.round(a * 100)}%`} className="absolute inset-y-0 w-px bg-fg/60" style={{ left: `${Math.min(100, a * 100)}%` }} />)}
      </div>
      <div className="mt-1 tabular-nums text-mute">{(u * 100).toFixed(0)}%{b.alertAt.length > 0 && ` · alert at ${b.alertAt.map((a) => `${Math.round(a * 100)}%`).join(", ")}`}</div>
    </div>
  );
}

export function Budgets() {
  const { data, error, isLoading } = useBudgets();
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Empty>Loading…</Empty>;
  if (data.budgets.length === 0) {
    return (
      <Card title="Cost and budgets">
        <Empty>No budgets are configured. Add a <Mono>Budget</Mono> (scope user, group, ring or org) to the policy repo; spend appears here once the gateway reports usage. See the cost budgets guide.</Empty>
      </Card>
    );
  }
  return (
    <div className="space-y-5">
      {scopes.map((scope) => {
        const rows = data.budgets.filter((b) => b.scope === scope).sort((a, b) => utilization(b) - utilization(a));
        if (rows.length === 0) return null;
        return (
          <Card key={scope} title={`${scope} budgets · ${rows.length}`} right={<span className="text-mute">highest utilization first</span>}>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <caption className="sr-only">Spend against limit for {scope} budgets</caption>
                <thead className="text-[11px] tracking-wide text-mute uppercase">
                  <tr className="border-b border-line">{["Budget", "Key", "Spend", "Limit", "Utilization", "Window", "Mode", "Resets"].map((c) => <th key={c} scope="col" className="px-4 py-2 font-medium">{c}</th>)}</tr>
                </thead>
                <tbody>
                  {rows.map((b) => (
                    <tr key={`${b.budget}/${b.key}`} className="border-b border-line align-top last:border-0 hover:bg-panel2">
                      <td className="px-4 py-2 font-medium">{b.budget}</td>
                      <td className="px-4 py-2"><Mono>{b.key || "—"}</Mono></td>
                      <td className="px-4 py-2 tabular-nums">{usd(b.spentUSD)}<div className="text-mute">{num(b.spentTokens)} tokens</div></td>
                      <td className="px-4 py-2 tabular-nums">{b.limitUSD ? usd(b.limitUSD) : "—"}<div className="text-mute">{b.limitTokens ? `${num(b.limitTokens)} tokens` : "no token limit"}</div></td>
                      <td className="px-4 py-2"><Bar b={b} /></td>
                      <td className="px-4 py-2">{b.window}{b.period && <div className="text-mute">{b.period}</div>}</td>
                      <td className="px-4 py-2"><Pill tone={b.action === "enforce" ? "bad" : "warn"}>{b.action}</Pill></td>
                      <td className="px-4 py-2 whitespace-nowrap text-mute" title={b.resetAt}>{new Date(b.resetAt).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
