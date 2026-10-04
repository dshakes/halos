// The two self-service journeys against a running `make demo` (make demo-e2e),
// in the order a real day happens: an admin opens an empty console, a developer
// enrolls a machine from the kiosk without any admin, the admin then sees it.
// Tests in this file depend on each other's state and run in order (one worker).
import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { OUT, expectHealthy, expectNoHorizontalScroll, login, settle, shoot, watch } from "./helpers";

const CONSOLE_PORT = process.env.HALO_DEMO_CONSOLE_PORT ?? "18080";
const DL_PORT = process.env.HALO_DEMO_DL_PORT ?? "18082";
const HOSTNAME = "e2e-laptop";

// Run the kiosk's laptop command in a throwaway container on the demo network, as
// the developer would on their machine; then one halod cycle, as the service would.
// The command is generated for this laptop (localhost URLs); socat maps those ports
// to the services, and registry:5000 resolves on the network.
function enrollInContainer(cmd: string): string {
  return execFileSync("docker", ["run", "--rm", "--hostname", HOSTNAME, "--network", "halos-demo_default", "-e", `CMD=${cmd}`, "alpine:3.20", "sh", "-euc", `
    apk add -q --no-cache curl socat >/dev/null
    socat TCP-LISTEN:${CONSOLE_PORT},fork,reuseaddr TCP:halo-server:8080 &
    socat TCP-LISTEN:${DL_PORT},fork,reuseaddr TCP:downloads:8080 &
    sleep 1
    sh -c "$CMD"
    /usr/local/lib/halos/halod once --install=false
    /usr/local/lib/halos/halod status`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 240_000 });
}

const kiosk = async (page: Page) => {
  await page.goto("/#/kiosk");
  await settle(page);
};

// Overview tiles are links; this is the one with the given label.
const tile = (page: Page, label: string) => page.locator("main a", { has: page.locator("div", { hasText: new RegExp(`^${label}$`) }) });

// The journeys assume a fresh `make demo`. A re-run against a used stack skips the
// before-anyone-enrolled assertions rather than asserting a state that is gone.
async function fresh(page: Page): Promise<boolean> {
  const res = await page.request.get("/api/v1/fleet");
  return res.ok() && ((await res.json()) as { total: number }).total === 0;
}

test.beforeAll(() => mkdirSync(OUT, { recursive: true }));

test("admin: an empty console says what to do next", async ({ page }) => {
  const errs = watch(page);
  await login(page, "alice@acme.com");
  test.skip(!(await fresh(page)), "a device already reported: not a fresh demo");
  // Overview: every tile is a real number or state, and the empty fleet tells the admin where devices come from.
  await expect(tile(page, "Devices reporting")).toContainText("0");
  await expect(page.getByText("No device has reported yet.")).toBeVisible();
  await expect(tile(page, "Releases")).toContainText("healthy");
  await expect(tile(page, "Running experiments")).toContainText("3");
  await expect(tile(page, "Pending approvals")).toContainText("0");
  await expect(tile(page, "Kill switch")).toContainText(/armed, idle|not configured/);
  await expect(page.getByText("no release published")).toHaveCount(0); // the demo publishes every ring
  await expectHealthy(page, errs, "overview (empty fleet)");

  await page.goto("/#/fleet");
  await settle(page);
  await expect(page.getByText(/No device has reported yet/).first()).toBeVisible();
  await expect(page.getByText("sudo halod once").first()).toBeVisible();
  await expectHealthy(page, errs, "fleet (empty)");

  await page.goto("/#/approvals");
  await settle(page);
  await expect(page.getByText(/Inbox zero/)).toBeVisible();
  await expect(page.getByText("Nothing decided yet.")).toBeVisible();
  await expectHealthy(page, errs, "approvals (empty)");

  // The admin's kiosk shows calmly which launchers the server cannot run yet, and where to set them up.
  await kiosk(page);
  await expect(page.getByText(/is not set up yet/)).toContainText("https halodURL");
  await expect(page.getByRole("link", { name: "Setup guide" })).toHaveAttribute("href", /self-service-portal/);
  await expectHealthy(page, errs, "kiosk (admin)");
  const res = await page.request.post("/api/v1/launch/devcontainer", { headers: { Origin: new URL(page.url()).origin } });
  expect(res.status()).toBe(409);
  expect(((await res.json()) as { error: string }).error).toContain("https halodURL");
});

test("developer: from landing to an enrolled, compliant device, no admin involved", async ({ page }) => {
  const errs = watch(page);
  await login(page, "bob@acme.com");
  // 10-second understanding: what Halos gives them, in plain words, with their tools named.
  await expect(page.getByRole("heading", { name: "Hi, bob" })).toBeVisible();
  await expect(page.getByText(/Halos sets up .*claude-code.* and keeps them that way/)).toBeVisible();
  await expect(page.getByText(/rollout ring .*ring2-early.*: that decides which versions/)).toBeVisible();
  // Each harness card lists only the models its wire can reach.
  const card = (h: string) => page.locator("section", { has: page.getByText(h, { exact: true }) }).filter({ hasText: "Models" }).last();
  await expect(card("claude-code")).not.toContainText(/codex-default|gemini-default/);
  await expect(card("codex")).toContainText("codex-default");
  await expect(card("codex")).not.toContainText(/gemini-default|sonnet/);

  // Step 1: only setups that work are offered (the demo can run only the laptop one).
  const started = page.locator("section", { has: page.getByRole("heading", { name: /Pick where you code/ }) });
  await expect(started.getByRole("button")).toHaveText([/Set up my laptop/]);
  await expect(page.getByText("not set up yet")).toHaveCount(0);
  // Step 2 before enrolling: the empty state says what to do; step 3 says where to go when it breaks.
  const posture = page.getByTestId("posture");
  const isFresh = await fresh(page);
  if (isFresh) {
    await expect(posture).toContainText("no device yet");
    await expect(posture).toContainText("Pick a setup above");
    await expect(page.getByText("No device enrolled yet.")).toBeVisible();
  }
  const help = page.locator("section", { has: page.getByRole("heading", { name: /If something breaks/ }) });
  await expect(help).toContainText("sudo halod status");
  await expect(help).toContainText("device posture check failed");
  await expect(help.getByRole("link", { name: /Contact support/ })).toHaveAttribute("href", /^https:\/\//);
  await expectHealthy(page, errs, "kiosk before enrollment");
  await shoot(page, `${OUT}/kiosk-developer-before.png`);

  // Get the command; it comes with what happens next.
  await started.getByRole("button", { name: /Set up my laptop/ }).click();
  await settle(page);
  const bash = await page.locator("pre").filter({ hasText: "enroll.sh" }).first().innerText();
  expect(bash).toMatch(/^curl -fsSL http\S+\/enroll\.sh \| sh -s -- \S+$/);
  await expect(page.getByText(/expires in \d+:\d\d/)).toBeVisible();
  await expect(page.getByText("What happens next.")).toBeVisible();
  if (isFresh) await expect(posture).toContainText("Waiting for your machine");
  writeFileSync(`${OUT}/laptop.sh`, bash + "\n");

  // Run it where a developer would: a fresh machine (container). enroll.sh installs,
  // enrolls, and, lacking launchd/systemd there, prints the two commands to run instead.
  const out = enrollInContainer(bash);
  writeFileSync(`${OUT}/enroll.log`, out);
  expect(out).toContain("this machine is enrolled");
  expect(out).toContain("halod is not running yet (no launchd/systemd here)");
  expect(out).toContain("sudo /usr/local/lib/halos/halod once");
  expect(out).toMatch(/"ring":\s*"ring2-early"/); // halod status, after one cycle
  expect(out).toMatch(/"digest":\s*"sha256:/);

  // The kiosk notices by itself: enrolled, reported, compliant, with the ring release it applied.
  await expect(posture).toContainText("all set", { timeout: 60_000 });
  await expect(posture).toContainText("enrolled and compliant");
  const dev = page.locator("li", { hasText: HOSTNAME }).first(); // newest first; re-runs add more
  await expect(dev).toContainText("compliant");
  await expect(dev).toContainText("ring2-early");
  await expect(dev).toContainText(/release [0-9a-f]{8}/);
  await expect(dev).toContainText("claude-code"); // the pinned CLIs it is bringing in
  await expectHealthy(page, errs, "kiosk after enrollment");
  await shoot(page, `${OUT}/kiosk-developer-enrolled.png`);

  // Ask for the beta ring and watch the request's state, with what it means (on a re-run it was already asked).
  const beta = page.locator("section", { has: page.getByRole("heading", { name: "Try the beta" }) });
  const mine = page.locator("section", { has: page.getByRole("heading", { name: "My requests" }) });
  if (await beta.getByRole("button", { name: "Opt in" }).isVisible()) {
    await beta.getByRole("button", { name: "Opt in" }).click();
    await page.getByRole("textbox", { name: /Why do you need ring1-canary/ }).fill("e2e: trying the canary ring");
    await page.getByRole("button", { name: "Send" }).click();
    await settle(page);
    await expect(beta.getByText("requested")).toBeVisible();
    await expect(mine).toContainText("waiting for an admin");
    await expect(mine).toContainText("An admin reviews it");
  }
  await expect(mine).toContainText("ring1-canary");
  await expectHealthy(page, errs, "kiosk after requesting");

  // The developer's own "why this setup?" page explains their ring without an admin.
  await page.goto("/#/debug");
  await settle(page);
  await expect(page.getByText("Why do I get this setup?")).toBeVisible();
  await expect(page.getByText("ring2-early").first()).toBeVisible();
  await expectHealthy(page, errs, "developer: why this setup");
});

test("admin: the populated console, and every safe action is one click or a PR", async ({ page }) => {
  const errs = watch(page);
  await login(page, "alice@acme.com");
  await expect(tile(page, "Devices reporting")).toContainText(/[1-9]/);
  await expect(page.getByText("No device has reported yet.")).toHaveCount(0);
  const ring = page.locator("div", { hasText: /^2ring2-early/ }).first(); // the ring track
  await expect(ring).toContainText(/\b[1-9]\d* device/);
  await expect(ring).toContainText("in sync");
  await expectHealthy(page, errs, "overview (populated)");
  await shoot(page, `${OUT}/admin-overview.png`);

  // Fleet lists the device; its row opens the device page with the binding and last report.
  await page.goto("/#/fleet");
  await settle(page);
  const row = page.getByRole("row", { name: new RegExp(HOSTNAME) }).first(); // re-runs enroll the same hostname again
  await expect(row).toContainText("ring2-early");
  await expect(row).toContainText("bob@acme.com");
  await row.getByRole("link", { name: /Device details/ }).click();
  await settle(page);
  await expect(page.getByRole("heading", { name: HOSTNAME })).toBeVisible();
  await expect(page.getByText("active")).toBeVisible();
  await expect(page.getByText("bob@acme.com").first()).toBeVisible();
  await expect(page.locator("section", { hasText: /^Last report/ })).toContainText("ring2-early"); // survives a server restart; the history does not
  await expect(page.getByText(/Report history · \d+/)).toBeVisible();
  await expectHealthy(page, errs, "device detail");

  // Approvals: bob's request waits; approving is one click and opens a PR, never a merge.
  await page.goto("/#/approvals");
  await settle(page);
  const decided = page.locator("section", { has: page.getByRole("heading", { name: "Decided" }) });
  const pending = page.locator("section", { has: page.getByRole("heading", { name: /^Pending/ }) });
  const approve = pending.getByRole("button", { name: /Approve → open PR/ }).first();
  if (await approve.isVisible()) { // on a re-run the request was decided last time
    await expect(pending).toContainText("bob@acme.com");
    await expect(pending).toContainText("ring1-canary");
    await approve.click();
    await settle(page);
  }
  await expect(decided).toContainText("approved", { timeout: 60_000 });
  await expect(decided).toContainText("bob@acme.com");
  await expect(decided).toContainText(/PR|change proposed: /); // a GitHub PR link, or where the branch went (the demo has no GitHub)
  await expectHealthy(page, errs, "approvals after approving");

  // Releases: every ring has a verified pointer and the enrolled device converged on its ring's.
  await page.goto("/#/releases");
  await settle(page);
  await expect(page.getByText("No signed pointer published")).toHaveCount(0);
  await expect(page.getByText(/(\d+)\/\1 on current release/).first()).toBeVisible(); // every reporting device converged
  await expectHealthy(page, errs, "releases");

  // Experiments: state changes are PRs behind a confirmation; the kill switch needs a reason.
  await page.goto("/#/experiments");
  await settle(page);
  await expect(page.getByText(/status changes open a policy PR/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Kill switch" })).toBeDisabled(); // no reason typed yet
  await expectHealthy(page, errs, "experiments");

  // Audit: the enrollment and the approval are on the hash chain.
  await page.goto("/#/audit");
  await settle(page);
  await expect(page.getByText("Chain verified")).toBeVisible();
  await expect(page.locator("tbody").getByText("device.enroll").first()).toBeVisible();
  await expect(page.locator("tbody").getByText("request.approve").first()).toBeVisible();
  await expectHealthy(page, errs, "audit");
});

test.describe("phone width", () => {
  test.use({ viewport: { width: 375, height: 812 } });

  test("kiosk and console pages fit a 375px screen", async ({ page }) => {
    const errs = watch(page);
    await login(page, "bob@acme.com");
    await kiosk(page);
    await expect(page.getByRole("heading", { name: "Hi, bob" })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    await expectNoHorizontalScroll(page, "kiosk (developer, mobile)");
    await expect(page.getByTestId("posture")).toContainText("all set");
    await page.locator("section", { has: page.getByRole("heading", { name: /Pick where you code/ }) }).getByRole("button", { name: /Set up my laptop/ }).click();
    await settle(page);
    await expect(page.locator("pre").filter({ hasText: "enroll.sh" }).first()).toBeVisible();
    await expectNoHorizontalScroll(page, "kiosk with the laptop command (mobile)");
    await expectHealthy(page, errs, "kiosk (developer, mobile)");
    await shoot(page, `${OUT}/kiosk-developer-mobile.png`);

    await login(page, "alice@acme.com");
    for (const r of ["", "kiosk", "fleet", "approvals", "releases"]) {
      await page.goto(`/#/${r}`);
      await settle(page);
      await expectNoHorizontalScroll(page, `#/${r} (admin, mobile)`);
    }
    await expectHealthy(page, errs, "console (admin, mobile)");
  });
});

test("screenshots: every page, desktop and phone", async ({ browser }) => {
  for (const [user, routes, tag] of [["alice@acme.com", ["", "kiosk", "fleet", "releases", "experiments", "toggles", "policy", "debug", "approvals", "audit"], "admin"], ["bob@acme.com", ["kiosk", "debug"], "developer"]] as const) {
    for (const [width, height, vp] of [[1400, 1000, "desktop"], [375, 812, "mobile"]] as const) {
      const ctx = await browser.newContext({ viewport: { width, height } });
      const page = await ctx.newPage();
      await login(page, user);
      for (const r of routes) {
        await page.goto(`/#/${r}`);
        await settle(page);
        await shoot(page, `${OUT}/shots/${tag}-${vp}-${r || "home"}.png`);
      }
      await ctx.close();
    }
  }
});
