// Click-through of every console page and button against a running `make demo`
// (make demo-e2e). Fails on any console error, uncaught exception, visible
// error box (role=alert) or text that only appears when something is broken.
import { expect, test, type Locator, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";

const OUT = process.env.HALO_E2E_OUT ?? "e2e-results/out";
const BROKEN = /not configured|internal server error|failed to fetch|unexpected token|is not a function|cannot read propert|\[object Object\]|\bNaN\b|\bundefined\b|invalid input|policy not loaded/i;
const ADMIN_ROUTES = ["", "kiosk", "fleet", "releases", "experiments", "toggles", "policy", "debug", "approvals", "audit"];

function watch(page: Page): string[] {
  const errs: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") errs.push(`console error: ${m.text()} (${m.location().url})`);
  });
  page.on("pageerror", (e) => errs.push(`uncaught: ${e.message}`));
  return errs;
}

async function login(page: Page, user: string) {
  await page.goto("/auth/login");
  await page.getByRole("link", { name: user }).click();
  await page.waitForURL((u) => u.pathname === "/"); // back from the IdP picker (/authorize) via /auth/callback
  await settle(page);
}

async function settle(page: Page) {
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(200);
}

async function expectHealthy(page: Page, errs: string[], where: string) {
  const alerts = await page.locator('[role="alert"]:visible').allInnerTexts();
  const broken = (await page.locator("body").innerText()).match(BROKEN);
  const problems = [...errs.splice(0), ...alerts.map((a) => `error box: ${a}`), ...(broken ? [`broken text: "${broken[0]}"`] : [])];
  expect.soft(problems, where).toEqual([]); // soft: one run reports every broken page and button
}

// Fill whatever form a click revealed with plausible values, then submit it.
// The element to drive: the topmost open dialog (drawers and modals stack; a backdrop covers what is beneath), else main.
async function scopeOf(page: Page): Promise<Locator> {
  const dialogs = page.locator('[role="dialog"]:visible');
  return (await dialogs.count()) > 0 ? dialogs.last() : page.locator("main");
}

async function fillAndSubmit(page: Page, scope: Locator) {
  const inputs = scope.locator("input[type=text]:visible, input:not([type]):visible, textarea:visible");
  let filled = 0;
  for (let i = 0; i < (await inputs.count()); i++) {
    const el = inputs.nth(i);
    if ((await el.inputValue()) !== "" || !(await el.isEditable())) continue;
    const label = await el.evaluate((e: HTMLInputElement) => e.labels?.[0]?.textContent ?? "");
    const hint = `${label} ${(await el.getAttribute("placeholder")) ?? ""} ${(await el.getAttribute("aria-label")) ?? ""}`.toLowerCase();
    if (/remove/.test(hint)) continue; // removing something that was never there is a 422 the server is right to send
    await el.fill(/group/.test(hint) ? "eng" : /ring/.test(hint) ? "ring2-early" : /user|email|@/.test(hint) ? "bob@acme.com" : "e2e click-through");
    filled++;
  }
  if (filled === 0) return false;
  const submit = scope.locator("button[type=submit]:visible:enabled, form button:not([type]):visible:enabled").first();
  if (await submit.count()) {
    await submit.click({ timeout: 15_000 });
    await settle(page);
  }
  return true;
}

async function clickEverything(page: Page, errs: string[], route: string) {
  await page.goto(`/#/${route}`);
  await settle(page);
  await expectHealthy(page, errs, `#/${route} on load`);
  // A route that opens a drawer or modal (e.g. #/toggles/<name>) is driven inside it: the backdrop covers the rest.
  await fillAndSubmit(page, await scopeOf(page)); // forms that are there from the start (e.g. the assignment debugger)
  await expectHealthy(page, errs, `#/${route} initial form`);
  const count = await (await scopeOf(page)).locator("button:visible").count();
  for (let i = 0; i < count; i++) {
    await page.goto(`/#/${route}`);
    await page.reload(); // fresh state per button: a hash-only goto keeps open drawers and results
    await settle(page);
    const btn = (await scopeOf(page)).locator("button:visible").nth(i);
    if (!(await btn.count()) || !(await btn.isEnabled())) continue;
    const name = (await btn.innerText()).trim().replace(/\s+/g, " ").slice(0, 40);
    // A click that stays blocked (backdrop, overlay) is itself a finding: report it instead of spending the test budget.
    await btn.click({ timeout: 15_000 }).catch((e: Error) => errs.push(`click "${name}" blocked: ${e.message.split("\n")[0]}`));
    await settle(page);
    await expectHealthy(page, errs, `#/${route} after clicking "${name}"`);
    if (await fillAndSubmit(page, await scopeOf(page))) await expectHealthy(page, errs, `#/${route} after submitting the form "${name}" opened`);
    await page.keyboard.press("Escape");
  }
}

async function routes(page: Page, start: string[]): Promise<string[]> {
  const seen = new Set(start);
  for (const r of start) {
    await page.goto(`/#/${r}`);
    await settle(page);
    for (const href of await page.locator('main a[href^="#/"]').evaluateAll((as) => as.map((a) => a.getAttribute("href") ?? ""))) {
      seen.add(href.replace(/^#\//, ""));
    }
  }
  return [...seen].slice(0, 40);
}

test("admin: every page and button", async ({ page }) => {
  const errs = watch(page);
  await login(page, "alice@acme.com");
  for (const r of await routes(page, ADMIN_ROUTES)) await clickEverything(page, errs, r);
});

test("user: every page and button", async ({ page }) => {
  const errs = watch(page);
  await login(page, "bob@acme.com");
  for (const r of ["", "kiosk", "debug"]) await clickEverything(page, errs, r);
});

test("kiosk: launchers produce working output; unconfigured ones stay calm", async ({ page }) => {
  const errs = watch(page);
  mkdirSync(OUT, { recursive: true });
  await login(page, "bob@acme.com");
  await page.goto("/#/kiosk");
  await settle(page);
  // A developer only sees launchers that work (the demo can run only the laptop one).
  const started = page.locator("section", { has: page.getByRole("heading", { name: "Get started" }) });
  await expect(started.getByRole("button")).toHaveText([/Set up my laptop/]);
  await expect(page.getByText("not set up yet")).toHaveCount(0);

  // Each harness card lists only the models its wire can reach.
  const card = (h: string) => page.locator("section", { has: page.getByText(h, { exact: true }) }).filter({ hasText: "Models" }).last();
  await expect(card("claude-code")).not.toContainText(/codex-default|gemini-default/);
  await expect(card("codex")).toContainText("codex-default");
  await expect(card("codex")).not.toContainText(/gemini-default|sonnet/);

  await started.getByRole("button", { name: /Set up my laptop/ }).click();
  await settle(page);
  const bash = await page.locator("pre").filter({ hasText: "enroll.sh" }).first().innerText();
  expect(bash).toMatch(/^curl -fsSL http\S+\/enroll\.sh \| sh -s -- \S+$/);
  writeFileSync(`${OUT}/laptop.sh`, bash + "\n"); // scripts/demo-e2e.sh runs it in a container
  await expectHealthy(page, errs, "kiosk launchers (developer)");
  await page.screenshot({ path: `${OUT}/kiosk-developer.png`, fullPage: true });

  // An admin sees what is missing, calmly, with where to set it; API clients keep the 409.
  await login(page, "alice@acme.com");
  await page.goto("/#/kiosk");
  await settle(page);
  await expect(page.getByText(/is not set up yet/)).toContainText("https halodURL");
  await expect(page.getByRole("link", { name: "Setup guide" })).toHaveAttribute("href", /self-service-portal/);
  await expectHealthy(page, errs, "kiosk launchers (admin)");
  const res = await page.request.post("/api/v1/launch/devcontainer", { headers: { Origin: new URL(page.url()).origin } });
  expect(res.status()).toBe(409);
  expect(((await res.json()) as { error: string }).error).toContain("https halodURL");
  await page.screenshot({ path: `${OUT}/kiosk-admin.png`, fullPage: true });
});
