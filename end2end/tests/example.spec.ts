import { test, expect } from "@playwright/test";

test("homepage has title and heading text", async ({ page }) => {
    await page.goto("http://127.0.0.1:3000/");

    // Updated to your actual title
    await expect(page).toHaveTitle("Leptos Auth Demo");

    // Updated to your actual H1
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
        "Modern auth demo, built with Leptos & Axum",
    );
});
