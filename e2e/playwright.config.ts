import { defineConfig, devices } from "@playwright/test";

// Two projects run in parallel, each pinned to the toolkit's port
// (3000 SOC, 3001 OSINT). A single Playwright run covers both frontends
// so CI gets one consolidated report. The compose stack must already
// be up - CI starts it in the `e2e` job, not via webServer here, so
// that we don't tear down volumes between per-project runs.

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 5_000 },
  fullyParallel: false, // SOC and OSINT hit shared backends; keep deterministic
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"]],
  use: {
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "soc-toolkit",
      testMatch: /soc\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: process.env.SOC_BASE_URL ?? "http://localhost:3000",
      },
    },
    {
      name: "osint-toolkit",
      testMatch: /osint\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: process.env.OSINT_BASE_URL ?? "http://localhost:3001",
      },
    },
  ],
});
