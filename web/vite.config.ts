import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3000,
    proxy: {
      // ws:true forwards the HTTP/1.1 upgrade handshake — without it the
      // dev server proxies /api/v1/ws as a plain GET (HTTP 426 loop).
      "/api": { target: "http://localhost:8080", changeOrigin: true, ws: true },
      "/healthz": { target: "http://localhost:8080", changeOrigin: true },
      "/readyz": { target: "http://localhost:8080", changeOrigin: true },
    },
  },
});
