import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run dev` proxies the API to a local halo-server on :8080.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/api": "http://localhost:8080", "/healthz": "http://localhost:8080" } },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
