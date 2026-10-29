import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@shared": resolve(dir, "../shared"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8787", changeOrigin: true },
      "/proxy": { target: "http://localhost:8787", changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    chunkSizeWarningLimit: 1200,
  },
});
