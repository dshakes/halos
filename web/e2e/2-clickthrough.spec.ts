// Click-through of every console page and button against a running `make demo`
// (make demo-e2e). Fails on any console error, uncaught exception, visible
// error box (role=alert) or text that only appears when something is broken.
// Runs after 1-journeys.spec.ts (files run in name order with one worker).
import { test, type Locator, type Page } from "@playwright/test";
import { expectHealthy, login, settle, watch } from "./helpers";

const ADMIN_ROUTES = ["", "kiosk", "fleet", "releases", "experiments", "toggles", "policy", "debug", "approvals", "audit"];

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
