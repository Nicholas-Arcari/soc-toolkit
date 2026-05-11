import { expect, test } from "@playwright/test";

test.describe("OSINT toolkit smoke", () => {
  test("dashboard loads and sidebar nav is intact", async ({ page }) => {
    await page.goto("/");
    // Both the sidebar and the main region render an <h1>; scope the
    // visibility check to the main region so strict mode is happy.
    await expect(
      page.getByRole("main").getByRole("heading", { level: 1 }),
    ).toBeVisible();
    // Module links live in the sidebar's <nav>; scoping avoids colliding
    // with the dashboard cards that also link to the same routes.
    const nav = page.getByRole("complementary").getByRole("navigation");
    await expect(nav.getByRole("link", { name: /Targets/i })).toBeVisible();
    await expect(nav.getByRole("link", { name: /Investigate/i })).toBeVisible();
  });

  test("create a target with the authorization checkbox", async ({ page }) => {
    await page.goto("/targets");

    // Every OSINT install shows the ethics banner prominently; the
    // "authorized scan" checkbox is mandatory for target creation.
    await page.getByRole("button", { name: /New target|Add target|Create target/i }).first().click();

    const nameInput = page.getByLabel(/Name|Target name/i).first();
    await nameInput.fill(`smoke-${Date.now()}`);

    const scope = page.getByLabel(/Scope|Domains/i).first();
    if (await scope.isVisible()) {
      await scope.fill("example.com");
    }

    // The authorization checkbox is an explicit gate on target creation.
    // The form is rejected until it's checked - we verify the happy
    // path where the operator asserts authorization.
    const authCheckbox = page.getByRole("checkbox", { name: /authorized|authorize/i });
    await authCheckbox.check();

    await page.getByRole("button", { name: /Create|Save/i }).first().click();

    // After creation the target list should show our new row.
    await expect(page.getByText(/smoke-\d+/)).toBeVisible({ timeout: 10_000 });
  });
});
