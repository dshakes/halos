import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";

// The server CSP has no unsafe-eval: without jitless, zod probes `new Function` and
// every page load logs a CSP violation (the probe's throw is caught, the report is not).
z.config({ jitless: true });

// Go encodes nil slices/maps as null; normalise so the UI never sees null.
const arr = <T extends z.ZodType>(t: T) => z.array(t).nullish().transform((v) => v ?? []);
const rec = <T extends z.ZodType>(t: T) => z.record(z.string(), t).nullish().transform((v) => v ?? {});

const Host = z.object({
  hostname: z.string(),
  device: z.string().optional(), // set only for device-token reports; keys the detail page
  user: z.string(),
  ring: z.string(),
  digest: z.string(),
  harnesses: rec(z.object({ want: z.string(), installed: z.string() })),
  drift: arr(z.string()),
  lastError: z.string().optional(),
  errorCode: z.string().optional(),
  time: z.string(),
  lastSeen: z.string(),
});
export type Host = z.infer<typeof Host>;

const RingStats = z.object({
  ring: z.string(),
  hosts: z.number(),
  percent: z.number(),
  driftHosts: z.number(),
  digests: rec(z.number()),
  versions: rec(rec(z.number())),
});
export type RingStats = z.infer<typeof RingStats>;

const Fleet = z.object({ hosts: arr(Host), rings: arr(RingStats), total: z.number(), driftHosts: z.number() });

const Goal = z.object({ metric: z.string(), direction: z.string(), maxRegression: z.number().optional() });
const GuardrailStatus = z.enum(["pass", "fail", "inconclusive"]);
export type GuardrailStatus = z.infer<typeof GuardrailStatus>;

const Verdict = z.object({
  experiment: z.string(),
  verdict: z.enum(["promote", "rollback", "continue", "expired"]),
  reason: z.string(),
  control: z.string(),
  treatment: z.string(),
  nControl: z.number(),
  nTreatment: z.number(),
  pValue: z.number(),
  effect: z.number(),
  effectLower: z.number().optional(),
  effectUpper: z.number().optional(),
  guardrails: arr(
    z.object({
      metric: z.string(),
      result: z.object({
        status: GuardrailStatus,
        regression: z.number(),
        lower: z.number(),
        upper: z.number(),
        maxRegression: z.number(),
      }),
    }),
  ),
  evaluatedAt: z.string().optional(),
});
export type Verdict = z.infer<typeof Verdict>;

const Experiment = z.object({
  name: z.string(),
  type: z.string(),
  axis: z.string(),
  status: z.string(),
  rings: arr(z.string()),
  variants: arr(
    z.object({ name: z.string(), weight: z.number(), profile: z.string().optional(), control: z.boolean().optional(), routes: rec(z.object({ upstream: z.string(), model: z.string() })) }),
  ),
  sampleRate: z.number().optional(),
  metrics: z.object({ primary: Goal, guardrails: arr(Goal) }),
  stopping: z.object({ method: z.string(), alpha: z.number().optional(), minSamples: z.number().optional(), maxDays: z.number().optional(), maxSpendUSD: z.number().optional() }),
  verdict: Verdict.optional(),
});
export type Experiment = z.infer<typeof Experiment>;

const Ring = z.object({
  name: z.string(),
  order: z.number(),
  profile: z.string(),
  release: z.string().optional(),
  membership: z.object({ groups: arr(z.string()), percent: z.number().optional(), default: z.boolean().optional() }),
  resolved: z.record(z.string(), z.unknown()).optional(),
  error: z.string().optional(),
});
export type Ring = z.infer<typeof Ring>;

const Policy = z.object({
  org: z.string(),
  rings: arr(Ring),
  profiles: arr(z.string()),
  experiments: arr(Experiment),
  issues: arr(z.object({ severity: z.string(), path: z.string(), message: z.string() })),
});

const Whoami = z.object({
  user: z.string(),
  groups: arr(z.string()),
  ring: z.string(),
  profile: z.string().optional(),
  release: z.string().optional(),
  assignments: arr(z.object({ experiment: z.string(), status: z.string(), variant: z.string().optional(), control: z.boolean().optional() })),
});

const Harnesses = rec(arr(z.string()));

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function call<T extends z.ZodType>(method: string, path: string, schema: T, body?: unknown): Promise<z.infer<T>> {
  const res = await fetch(path, {
    method,
    headers: { Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const j: unknown = await res.json().catch(() => null);
    const msg = z.object({ error: z.string() }).safeParse(j);
    throw new ApiError(res.status, msg.success ? msg.data.error : `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return schema.parse(undefined); // e.g. revoke: no body
  return schema.parse(await res.json());
}
const get = <T extends z.ZodType>(path: string, schema: T) => call("GET", path, schema);

const Me = z.object({
  id: z.string(),
  groups: arr(z.string()),
  admin: z.boolean(),
  ring: z.string(),
  release: z.string().optional(),
  variants: arr(z.object({ experiment: z.string(), status: z.string(), variant: z.string().optional(), control: z.boolean().optional() })),
  profile: z
    .object({
      name: z.string(),
      harnesses: rec(z.string()),
      models: arr(z.string()),
      defaultModel: z.string(),
      mcpServers: arr(z.string()),
      sandbox: z.string().optional(),
      harnessModels: rec(arr(z.string())),
      harnessDefault: rec(z.string()),
    })
    .optional(),
  selfService: z.boolean(),
  launchers: arr(z.string()),
  launcherSetup: arr(z.object({ launcher: z.string(), missing: z.string() })),
  requestable: arr(z.string()),
  optInRings: arr(z.string()),
  supportURL: z.string().optional(),
  devInsecure: z.boolean().optional(),
});
export type Me = z.infer<typeof Me>;

const Catalog = z.object({
  harnesses: arr(z.object({ name: z.string(), version: z.string() })),
  launchers: arr(z.string()),
  items: arr(z.object({ kind: z.string(), item: z.string(), desc: z.string().optional() })),
});

const Launch = z.object({
  launcher: z.string(),
  filename: z.string().optional(),
  snippet: z.string().optional(),
  url: z.string().optional(),
  token: z.string().optional(),
  expiresAt: z.string().optional(),
  ttlSeconds: z.number().optional(),
  bash: z.string().optional(),
  powershell: z.string().optional(),
});
export type Launch = z.infer<typeof Launch>;

const AccessRequest = z.object({
  id: z.string(),
  user: z.string(),
  kind: z.string(),
  item: z.string(),
  justification: z.string(),
  ring: z.string().optional(),
  status: z.enum(["pending", "approving", "approved", "denied"]),
  createdAt: z.string(),
  decidedBy: z.string().optional(),
  prURL: z.string().optional(),
  note: z.string().optional(),
});
export type AccessRequest = z.infer<typeof AccessRequest>;

export const useMe = () => useQuery({ queryKey: ["me"], queryFn: () => get("/api/v1/me", Me), retry: false });

const DeviceBinding = z.object({
  id: z.string(),
  userID: z.string(),
  groups: arr(z.string()),
  createdAt: z.string(),
  lastSeen: z.string(),
  lastAuth: z.string().optional(),
  expiresAt: z.string().optional(),
  revoked: z.boolean(),
});
const MyDevices = z.object({
  devices: arr(z.object({ device: DeviceBinding, last: Host.optional(), expired: z.boolean() })),
  posture: z.object({ compliant: z.boolean(), reason: z.string().optional() }),
});
export type MyDevices = z.infer<typeof MyDevices>;
/** The caller's own devices and the gateway's posture verdict for them; polls fast while a device is expected. */
export const useMyDevices = (fast: boolean) =>
  useQuery({ queryKey: ["me", "devices"], queryFn: () => get("/api/v1/me/devices", MyDevices), refetchInterval: fast ? 3_000 : 15_000 });
export const useCatalog = (enabled: boolean) => useQuery({ queryKey: ["catalog"], queryFn: () => get("/api/v1/catalog", Catalog), enabled });
export const useRequests = (enabled = true) => useQuery({ queryKey: ["requests"], queryFn: () => get("/api/v1/requests", z.array(AccessRequest)), enabled, refetchInterval: 20_000 });
export const useLaunch = () => useMutation({ mutationFn: (launcher: string) => call("POST", `/api/v1/launch/${encodeURIComponent(launcher)}`, Launch) });
export function useCreateRequest() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { kind: string; item: string; justification: string }) => call("POST", "/api/v1/requests", AccessRequest, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["requests"] }),
  });
}
export function useDecide() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: { id: string; action: "approve" | "deny" }) => call("POST", `/api/v1/requests/${encodeURIComponent(a.id)}/${a.action}`, AccessRequest),
    onSettled: () => qc.invalidateQueries({ queryKey: ["requests"] }),
  });
}

export const useFleet = () => useQuery({ queryKey: ["fleet"], queryFn: () => get("/api/v1/fleet", Fleet), refetchInterval: 15_000 });
export const usePolicy = () => useQuery({ queryKey: ["policy"], queryFn: () => get("/api/v1/policy", Policy) });
export const useExperiments = () => useQuery({ queryKey: ["experiments"], queryFn: () => get("/api/v1/experiments", z.array(Experiment)), refetchInterval: 30_000 });
export const useHarnesses = () => useQuery({ queryKey: ["harnesses"], queryFn: () => get("/api/v1/harnesses", Harnesses), staleTime: Infinity });
export const useWhoami = (user: string, groups: string) =>
  useQuery({
    queryKey: ["whoami", user, groups],
    queryFn: () => get(`/api/v1/whoami?${new URLSearchParams({ user, groups })}`, Whoami),
    enabled: user !== "",
  });

const ChannelRelease = z.object({
  channel: z.string(),
  published: z.boolean(),
  digest: z.string().optional(),
  seq: z.number().optional(),
  expiresAt: z.string().optional(),
  expired: z.boolean(),
  stale: z.boolean(),
  suspicious: z.boolean(),
  error: z.string().optional(),
  devices: z.number(),
});
export type ChannelRelease = z.infer<typeof ChannelRelease>;
const RingRelease = z.object({
  ring: z.string(),
  published: z.boolean(),
  org: z.string().optional(),
  digest: z.string().optional(),
  seq: z.number().optional(),
  issuedAt: z.string().optional(),
  expiresAt: z.string().optional(),
  expiresInSeconds: z.number().default(0),
  expired: z.boolean(),
  expiringSoon: z.boolean(),
  stale: z.boolean(),
  suspicious: z.boolean(),
  error: z.string().optional(),
  channels: arr(ChannelRelease),
  convergence: z.object({ total: z.number(), onDigest: z.number(), other: z.number(), digests: rec(z.number()) }),
  driftHosts: z.number(),
});
export type RingRelease = z.infer<typeof RingRelease>;
const Releases = z.object({ rings: arr(RingRelease), stale: z.boolean(), registry: z.string() });
export const useReleases = () => useQuery({ queryKey: ["releases"], queryFn: () => get("/api/v1/releases", Releases), refetchInterval: 30_000 });

const DeviceDetail = z.object({
  device: DeviceBinding,
  last: Host.optional(),
  history: arr(Host),
});
export const useDevice = (id: string) => useQuery({ queryKey: ["device", id], queryFn: () => get(`/api/v1/devices/${encodeURIComponent(id)}`, DeviceDetail), refetchInterval: 15_000 });
/** Revokes the device token: its next call gets 401 and the machine must re-enroll from the kiosk. */
export function useRevokeDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call("POST", `/api/v1/devices/${encodeURIComponent(id)}/revoke`, z.unknown()),
    onSettled: (_d, _e, id) => Promise.all([qc.invalidateQueries({ queryKey: ["device", id] }), qc.invalidateQueries({ queryKey: ["fleet"] })]),
  });
}

const AuditEntry = z.object({
  seq: z.number(),
  time: z.string(),
  actor: z.string(),
  action: z.string(),
  target: z.string().optional(),
  ip: z.string().optional(),
  requestId: z.string().optional(),
  details: rec(z.string()),
  hash: z.string(),
});
export type AuditEntry = z.infer<typeof AuditEntry>;
const Audit = z.object({ entries: arr(AuditEntry), next: z.number(), total: z.number(), verified: z.boolean(), verifyError: z.string().optional(), head: z.string() });
export const useAudit = (actor: string, action: string) =>
  useQuery({
    queryKey: ["audit", actor, action],
    queryFn: () => get(`/api/v1/audit?${new URLSearchParams({ limit: "200", ...(actor ? { actor } : {}), ...(action ? { action } : {}) })}`, Audit),
    refetchInterval: 30_000,
  });

// Optional server features, so the console renders e.g. the kill switch only where it exists.
const Capabilities = z.object({ killSwitch: z.boolean().optional() });
export const useCapabilities = () => useQuery({ queryKey: ["capabilities"], queryFn: () => get("/api/v1/capabilities", Capabilities), staleTime: Infinity, retry: false });

export type SettableStatus = "running" | "paused" | "concluded";
/** Opens a policy-repo PR; nothing changes until a human merges it. */
export function useSetExperimentStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: { name: string; status: SettableStatus }) => call("POST", `/api/v1/experiments/${encodeURIComponent(a.name)}/status`, z.object({ prURL: z.string() }), { status: a.status }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["experiments"] }),
  });
}
export function useKillExperiment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: { name: string; reason: string }) => {
      const reason = a.reason.trim();
      if (!reason) return Promise.reject(new Error("A reason is required to kill an experiment."));
      return call("POST", `/api/v1/experiments/${encodeURIComponent(a.name)}/kill`, z.unknown(), { reason });
    },
    onSettled: () => Promise.all([qc.invalidateQueries({ queryKey: ["kills"] }), qc.invalidateQueries({ queryKey: ["experiments"] })]),
  });
}

const KillRecord = z.object({ experiment: z.string(), killed: z.boolean(), by: z.string(), reason: z.string().optional(), at: z.string() });
export type KillRecord = z.infer<typeof KillRecord>;
const Kills = z.object({ version: z.number(), killed: arr(KillRecord) });
/** Admin-only; pass enabled=capabilities.killSwitch so it is never requested where the server lacks it. */
export const useKills = (enabled: boolean) => useQuery({ queryKey: ["kills"], queryFn: () => get("/api/v1/killswitch", Kills), enabled, refetchInterval: 15_000 });
export function useUnkillExperiment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: { name: string; reason: string }) => call("POST", `/api/v1/experiments/${encodeURIComponent(a.name)}/unkill`, z.object({ experiment: z.string(), killed: z.boolean(), changed: z.boolean() }), { reason: a.reason.trim() }),
    onSettled: () => Promise.all([qc.invalidateQueries({ queryKey: ["kills"] }), qc.invalidateQueries({ queryKey: ["experiments"] })]),
  });
}

// ---- feature toggles ----
const ToggleRule = z.object({
  name: z.string().optional(),
  rings: arr(z.string()),
  groups: arr(z.string()),
  users: arr(z.string()),
  percent: z.number().optional(),
  effect: z.string().optional(),
});
export type ToggleRule = z.infer<typeof ToggleRule>;
const ToggleKill = z.object({ by: z.string(), reason: z.string().optional(), at: z.string() });
const PatchSummary = z.object({ mcpServers: arr(z.string()), hooks: arr(z.string()), env: arr(z.string()), overrides: arr(z.string()) });
const Toggle = z.object({
  name: z.string(),
  description: z.string().optional(),
  owner: z.string(),
  expires: z.string().optional(),
  stale: z.boolean(),
  axis: z.string(),
  default: z.boolean(),
  rules: arr(ToggleRule),
  payload: z.object({ harnesses: rec(PatchSummary).optional(), routes: rec(z.string()).optional() }),
  kill: ToggleKill.nullish(),
});
export type Toggle = z.infer<typeof Toggle>;
const Toggles = z.object({ toggles: arr(Toggle), killEnabled: z.boolean() });
export const useToggles = () => useQuery({ queryKey: ["toggles"], queryFn: () => get("/api/v1/toggles", Toggles), refetchInterval: 15_000 });

const Preview = z.object({
  subject: z.object({ id: z.string(), groups: arr(z.string()), ring: z.string().optional() }),
  decision: z.object({ name: z.string(), on: z.boolean(), rule: z.number(), killed: z.boolean().optional(), why: z.string(), trace: arr(z.string()) }),
});
export type TogglePreview = z.infer<typeof Preview>;
const ToggleDetail = z.object({ toggle: Toggle, history: arr(AuditEntry), preview: Preview.nullish() });
/** The "who gets it?" tester: pass a user to get the evaluation and rule trace (same code as `halo toggle eval`). */
export const useToggle = (name: string, user: string, ring: string, groups: string) =>
  useQuery({
    queryKey: ["toggle", name, user, ring, groups],
    queryFn: () => get(`/api/v1/toggles/${encodeURIComponent(name)}?${new URLSearchParams({ ...(user ? { user } : {}), ...(ring ? { ring } : {}), ...(groups ? { groups } : {}) })}`, ToggleDetail),
    refetchInterval: 15_000,
  });

const invalidateToggles = (qc: ReturnType<typeof useQueryClient>) => Promise.all([qc.invalidateQueries({ queryKey: ["toggles"] }), qc.invalidateQueries({ queryKey: ["toggle"] })]);
/** Kill or restore a toggle fleet-wide through the signed kill list (no release, no PR). */
export function useToggleKill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: { name: string; kill: boolean; reason: string }) => {
      const reason = a.reason.trim();
      if (a.kill && !reason) return Promise.reject(new Error("A reason is required to kill a toggle."));
      return call("POST", `/api/v1/toggles/${encodeURIComponent(a.name)}/${a.kill ? "kill" : "unkill"}`, z.object({ toggle: z.string(), killed: z.boolean(), changed: z.boolean() }), { reason });
    },
    onSettled: () => invalidateToggles(qc),
  });
}

export interface ToggleProposal {
  reason: string;
  default?: boolean;
  expires?: string;
  rule?: string;
  percent?: number;
  addRings?: string[];
  removeRings?: string[];
  addGroups?: string[];
  removeGroups?: string[];
  addUsers?: string[];
  removeUsers?: string[];
}
/** Opens a policy-repo PR (validated first); nothing changes until a human merges it. */
export function useProposeToggle() {
  return useMutation({
    mutationFn: (a: { name: string; change: ToggleProposal }) => call("POST", `/api/v1/toggles/${encodeURIComponent(a.name)}/propose`, z.object({ prURL: z.string() }), a.change),
  });
}
