import { test, expect } from "@playwright/test";

test.describe("Auth + Credit Cards flow", () => {
    test("home page renders hero and nav links", async ({ page }) => {
        await page.goto("/");

        // Header nav (banner)
        const header = page.getByRole("banner");
        await expect(header.getByRole("link", { name: "Login" })).toBeVisible();
        await expect(
            header.getByRole("link", { name: "Register" }),
        ).toBeVisible();

        // Main hero section
        const main = page.getByRole("main");

        await expect(
            main.getByRole("heading", {
                name: "Modern auth demo, built with Leptos & Axum",
            }),
        ).toBeVisible();

        // Hero call-to-action buttons
        await expect(main.getByRole("link", { name: "Login" })).toBeVisible();
        await expect(
            main.getByRole("link", { name: "Create account" }),
        ).toBeVisible();
    });

    test("full happy path: register → login → cards CRUD", async ({ page }) => {
        const username = `user-${Date.now()}`;
        const password = "Password123!";

        // ── Register ────────────────────────────────────────────────────────
        await test.step("registers a new user", async () => {
            await page.goto("/register");

            await expect(
                page.getByRole("heading", { name: "Create your account" }),
            ).toBeVisible();

            await page.getByPlaceholder("Choose a username").fill(username);
            await page
                .getByPlaceholder("Create a secure password")
                .fill(password);

            await page.getByRole("button", { name: "Register" }).click();

            // After register you redirect to /login
            await expect(page).toHaveURL(/\/login$/);
        });

        // ── Login ───────────────────────────────────────────────────────────
        await test.step("logs in with the new account", async () => {
            await expect(
                page.getByRole("heading", { name: "Welcome back" }),
            ).toBeVisible();

            await page.getByPlaceholder("Enter your username").fill(username);
            await page.getByPlaceholder("••••••••").fill(password);

            await page.getByRole("button", { name: "Login" }).click();

            // Should land on dashboard
            await expect(page).toHaveURL(/\/dashboard$/);
            await expect(
                page.getByRole("heading", { name: "Credit cards" }),
            ).toBeVisible();

            await expect(
                page.getByText(`Signed in as ${username}`, { exact: false }),
            ).toBeVisible();
        });

        // ── Dashboard empty state ──────────────────────────────────────────
        await test.step("shows empty state when there are no cards", async () => {
            await expect(
                page.getByText(
                    "No cards yet. Add your first card using the form above.",
                    { exact: false },
                ),
            ).toBeVisible();
        });

        // ── Create card ────────────────────────────────────────────────────
        const brand = "HDFC";
        const last4 = "1234";
        const limit = "100000";
        const balance = "25000"; // NOTE: currently not persisted on create
        const nickname = "Travel card";

        await test.step("creates a new card", async () => {
            // Brand, last4, credit limit
            await page.getByPlaceholder("e.g. HDFC, SBI, Axis").fill(brand);
            await page.getByPlaceholder("1234").fill(last4);
            await page.getByPlaceholder("100000").fill(limit);

            // Current balance: filled in UI but not wired through create_card yet
            await page.getByLabel("Current balance").fill(balance);

            // Nickname
            await page.getByPlaceholder("e.g. Travel card").fill(nickname);

            await page.getByRole("button", { name: "Add card" }).click();

            // Card appears in list
            await expect(
                page
                    .locator(".card-tile")
                    .filter({ hasText: nickname })
                    .filter({ hasText: `•••• ${last4}` }),
            ).toBeVisible();

            await expect(
                page.getByText(`Limit₹${limit}`, { exact: false }),
            ).toBeVisible();

            // IMPORTANT:
            // Backend currently defaults current_balance to 0 on create.
            // When you wire balance through to create_card, change this to use `balance`.
            await expect(
                page.getByText("Balance₹0", { exact: false }),
            ).toBeVisible();
        });

        // ── Update card ────────────────────────────────────────────────────
        const newNickname = "Primary Travel card";
        const newBalance = "30000";

        await test.step("updates an existing card", async () => {
            const cardItem = page
                .locator(".card-tile")
                .filter({ hasText: nickname });

            await cardItem.getByRole("button", { name: "Edit" }).click();

            await page.getByPlaceholder("e.g. Travel card").fill(newNickname);
            await page.getByLabel("Current balance").fill(newBalance);

            await page.getByRole("button", { name: "Update card" }).click();

            await expect(
                page
                    .locator(".card-tile")
                    .filter({ hasText: newNickname })
                    .filter({ hasText: `•••• ${last4}` }),
            ).toBeVisible();

            await expect(
                page.getByText(`Balance₹${newBalance}`, { exact: false }),
            ).toBeVisible();
        });

        // ── Delete card ────────────────────────────────────────────────────
        await test.step("deletes the card and returns to empty state", async () => {
            const cardItem = page
                .locator(".card-tile")
                .filter({ hasText: newNickname });

            await cardItem.getByRole("button", { name: "Delete" }).click();

            await expect(
                page.getByText(
                    "No cards yet. Add your first card using the form above.",
                    { exact: false },
                ),
            ).toBeVisible();
        });

        // ── Logout ────────────────────────────────────────────────────────
        await test.step("logs out", async () => {
            await page.getByRole("button", { name: "Logout" }).click();

            await expect(page).toHaveURL(/\/login$/);

            await expect(
                page.getByRole("heading", { name: "Welcome back" }),
            ).toBeVisible();
        });
    });
});
