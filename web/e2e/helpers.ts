// Shared by the journey and click-through specs: login through the mock IdP,
// health checks that fail on anything a user would read as broken.
import { expect, type Page } from "@playwright/test";

export const OUT = process.env.HALO_E2E_OUT ?? "e2e-results/out";
export const BROKEN = /not configured|internal server error|failed to fetch|unexpected token|is not a function|cannot read propert|\[object Object\]|\bNaN\b|\bundefined\b|invalid input|policy not loaded/i;

export function watch(page: Page): string[] {
  const errs: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") errs.push(`console error: ${m.text()} (${m.location().url})`);
  });
  page.on("pageerror", (e) => errs.push(`uncaught: ${e.message}`));
  return errs;
}

export async function login(page: Page, user: string) {
  await page.goto("/auth/login");
  await page.getByRole("link", { name: user }).click();
  await page.waitForURL((u) => u.pathname === "/"); // back from the IdP picker (/authorize) via /auth/callback
  await settle(page);
}

export async function settle(page: Page) {
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(200);
}

export async function expectHealthy(page: Page, errs: string[], where: string) {
  const alerts = await page.locator('[role="alert"]:visible').allInnerTexts();
  const broken = (await page.locator("body").innerText()).match(BROKEN);
  const problems = [...errs.splice(0), ...alerts.map((a) => `error box: ${a}`), ...(broken ? [`broken text: "${broken[0]}"`] : [])];
  expect.soft(problems, where).toEqual([]); // soft: one run reports every broken page and button
}

/** The page must not scroll sideways: neither the document nor the scrolling <main>. */
export async function expectNoHorizontalScroll(page: Page, where: string) {
  const w = await page.evaluate(() => ({
    doc: document.documentElement.scrollWidth, win: window.innerWidth,
    main: document.querySelector("main")?.scrollWidth ?? 0, mainClient: document.querySelector("main")?.clientWidth ?? 0,
  }));
  expect.soft(w.doc, `${where}: document scrollWidth`).toBeLessThanOrEqual(w.win);
  expect.soft(w.main, `${where}: main scrollWidth`).toBeLessThanOrEqual(w.mainClient);
}

/** Full-page screenshot of a page whose <main> scrolls internally: grow the viewport to the content first. */
export async function shoot(page: Page, path: string) {
  const vp = page.viewportSize() ?? { width: 1400, height: 1000 };
  const h = await page.evaluate(() => Math.max(document.querySelector("main")?.scrollHeight ?? 0, document.querySelector("aside")?.scrollHeight ?? 0) + 48);
  await page.setViewportSize({ width: vp.width, height: Math.min(Math.max(vp.height, h), 6000) });
  await page.screenshot({ path });
  await page.setViewportSize(vp);
}
