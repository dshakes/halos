// Click-through of every console page and button against a running `make demo`
// (make demo-e2e). Fails on any console error, uncaught exception, visible
// error box (role=alert) or text that only appears when something is broken.
import { expect, test, type Page } from "@playwright/test";
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
  expect(problems, where).toEqual([]);
}

// Fill whatever form a click revealed with plausible values, then submit it.
async function fillAndSubmit(page: Page, scope: string) {
  const inputs = page.locator(`${scope} input[type=text]:visible, ${scope} input:not([type]):visible, ${scope} textarea:visible`);
  let filled = 0;
  for (let i = 0; i < (await inputs.count()); i++) {
    const el = inputs.nth(i);
    if ((await el.inputValue()) !== "" || !(await el.isEditable())) continue;
    const hint = `${(await el.getAttribute("placeholder")) ?? ""} ${(await el.getAttribute("aria-label")) ?? ""}`.toLowerCase();
    await el.fill(/group/.test(hint) ? "eng" : /ring/.test(hint) ? "ring2-early" : /user|email|@/.test(hint) ? "bob@acme.com" : "e2e click-through");
    filled++;
  }
  if (filled === 0) return false;
  const submit = page.locator(`${scope} button[type=submit]:visible:enabled, ${scope} form button:not([type]):visible:enabled`).first();
  if (await submit.count()) {
    await submit.click();
    await settle(page);
  }
  return true;
}

async function clickEverything(page: Page, errs: string[], route: string) {
  await page.goto(`/#/${route}`);
  await settle(page);
  await expectHealthy(page, errs, `#/${route} on load`);
  await fillAndSubmit(page, "main"); // forms that are there from the start (e.g. the assignment debugger)
  await expectHealthy(page, errs, `#/${route} initial form`);
  const count = await page.locator("main button:visible").count();
  for (let i = 0; i < count; i++) {
    await page.goto(`/#/${route}`); // fresh state per button
    await settle(page);
    const btn = page.locator("main button:visible").nth(i);
    if (!(await btn.count()) || !(await btn.isEnabled())) continue;
    const name = (await btn.innerText()).trim().replace(/\s+/g, " ").slice(0, 40);
    await btn.click();
    await settle(page);
    await expectHealthy(page, errs, `#/${route} after clicking "${name}"`);
    const dialog = (await page.locator('[role="dialog"]:visible').count()) > 0;
    if (await fillAndSubmit(page, dialog ? '[role="dialog"]' : "main")) await expectHealthy(page, errs, `#/${route} after submitting the form "${name}" opened`);
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
  // A user only sees launchers that work.
  await expect(page.getByRole("button", { name: /GitHub Codespaces/ })).toHaveCount(0);
  await expect(page.getByText("Not set up yet")).toHaveCount(0);

  // Each harness card lists only the models its wire can reach.
  const claude = page.locator("section", { has: page.getByText("claude-code", { exact: true }) }).last();
  await expect(claude).not.toContainText("codex-default");
  await expect(claude).not.toContainText("gemini-default");

  await page.getByRole("button", { name: /Set up my laptop/ }).click();
  await settle(page);
  const bash = await page.locator("pre").filter({ hasText: "enroll.sh" }).first().innerText();
  expect(bash).toMatch(/^curl -fsSL http\S+\/enroll\.sh \| sh -s -- \S+$/);
  writeFileSync(`${OUT}/laptop.sh`, bash + "\n");

  await page.getByRole("button", { name: /Dev container/ }).click();
  await settle(page);
  const snippet = await page.locator("pre").filter({ hasText: '"features"' }).first().innerText();
  writeFileSync(`${OUT}/devcontainer.json`, snippet);
  const dc = JSON.parse(snippet) as { features: Record<string, Record<string, unknown>> };
  expect(Object.keys(dc.features)).toHaveLength(1);
  await expectHealthy(page, errs, "kiosk launchers (user)");

  // An admin sees what is missing, calmly, with where to set it.
  await login(page, "alice@acme.com");
  await page.goto("/#/kiosk");
  await settle(page);
  await expect(page.getByText("Not set up yet")).toBeVisible();
  await expect(page.getByText("codespacesURL")).toBeVisible();
  await expectHealthy(page, errs, "kiosk launchers (admin)");
  await page.screenshot({ path: `${OUT}/kiosk-admin.png`, fullPage: true });
});
