import { defineConfig, devices } from "@playwright/test";
import * as dotenv from "dotenv";
import * as path from "path";

// Load .env from the Rust project root (`../.env`)
dotenv.config({ path: path.resolve(__dirname, "..", ".env") });

export default defineConfig({
    testDir: "./tests",

    use: {
        baseURL: "http://127.0.0.1:3000",
        trace: "on-first-retry",
    },

    projects: [
        {
            name: "chromium",
            use: devices["Desktop Chrome"],
        },
    ],

    webServer: {
        command: "sh -c 'cd .. && cargo leptos serve'",
        port: 3000,
        reuseExistingServer: !process.env.CI,
        timeout: 120000,

        // Pass the .env vars to the server
        env: {
            JWT_SECRET: process.env.JWT_SECRET,
            RUST_LOG: "info",
        },
    },
});
