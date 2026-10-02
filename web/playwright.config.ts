import { defineConfig } from "@playwright/test";

// Browser e2e against a running `make demo` (make demo-e2e). HALO_E2E_URL overrides the console URL.
export default defineConfig({
  testDir: "e2e",
  outputDir: "e2e-results",
  timeout: 300_000,
  workers: 1, // one demo stack, and the click-through mutates it
  reporter: [["list"]],
  use: {
    baseURL: process.env.HALO_E2E_URL ?? "http://localhost:18080",
    browserName: "chromium",
    headless: true,
    viewport: { width: 1400, height: 1000 },
    screenshot: "only-on-failure",
  },
});
