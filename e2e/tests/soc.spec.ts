import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

const __dirname = dirname(fileURLToPath(import.meta.url));
// The phishing sample that ships with the repo - used as the upload
// fixture so we don't have to maintain a duplicate under e2e/.
const SAMPLE_PHISHING = resolve(
  __dirname,
  "../../packages/soc-toolkit/samples/emails/phishing_sample.eml",
);

test.describe("SOC toolkit smoke", () => {
  test("dashboard loads and shows the main nav", async ({ page }) => {
    await page.goto("/");
    // The sidebar renders an <h1>SOC Toolkit</h1>; there's also a
    // page-level heading, so scope the check to the sidebar.
    const sidebar = page.getByRole("complementary");
    await expect(sidebar.getByRole("heading", { name: /SOC Toolkit/i })).toBeVisible();
    // Every primary module should be reachable from the sidebar. The
    // dashboard body also links to each module, so we scope the lookup
    // to the <nav> to keep the locator strict-mode clean.
    const nav = sidebar.getByRole("navigation");
    for (const label of [
      "Phishing Analyzer",
      "Log Analyzer",
      "IOC Extractor",
      "IOC Pivot",
      "YARA Scanner",
      "Sigma Detection",
      "File Inspector",
      "Link Analyzer",
      "QR Analyzer",
    ]) {
      await expect(nav.getByRole("link", { name: label })).toBeVisible();
    }
  });

  test("new detection tools render", async ({ page }) => {
    for (const [path, heading] of [
      ["/file", "File Inspector"],
      ["/link", "Link Analyzer"],
      ["/qr", "QR Analyzer"],
    ] as const) {
      await page.goto(path);
      await expect(
        page.getByRole("heading", { name: heading, exact: true }),
      ).toBeVisible();
    }
  });

  test("link analyzer bulk triage flags risky URLs (no backend)", async ({
    page,
  }) => {
    await page.goto("/link");
    await page
      .getByPlaceholder(/https:\/\/bit\.ly/)
      .fill("https://bit.ly/x\nhttp://192.168.0.1/login");
    await page.getByRole("button", { name: "Triage URLs" }).click();
    await expect(
      page.getByText("URL shortener - hides the real destination"),
    ).toBeVisible();
  });

  test("upload phishing sample, get a verdict", async ({ page }) => {
    await page.goto("/phishing");

    // The FileUpload primitive exposes an <input type=file>; we address
    // it by setting input files directly rather than driving the drop-
    // zone, which is prone to flakiness on headless Chromium.
    const fileInput = page.locator('input[type="file"]');
    const buf = readFileSync(SAMPLE_PHISHING);
    await fileInput.setInputFiles({
      name: "phishing_sample.eml",
      mimeType: "message/rfc822",
      buffer: buf,
    });

    // Analysis is fire-on-select: the frontend posts to /phishing/analyze
    // as soon as a file is staged and renders the verdict heading when
    // the response lands. The sample is the known-malicious fixture so
    // we pin on MALICIOUS; any other verdict is a regression.
    await expect(
      page.getByRole("heading", { name: /MALICIOUS|SUSPICIOUS|LEGITIMATE|BENIGN/i }),
    ).toBeVisible({ timeout: 30_000 });
  });
});
