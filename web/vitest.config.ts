import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Unit tests live next to their modules; Playwright e2e specs (tests/*.spec.ts)
// run through `npm run test:e2e` and are intentionally excluded here.
export default defineConfig({
  resolve: {
    // Mirror the app's vite alias so lib modules that import "@/..."
    // resolve the same way under vitest as they do under vite.
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  test: {
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    environment: "node",
  },
});
