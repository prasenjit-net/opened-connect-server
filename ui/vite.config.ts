import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Development API requests are proxied to the Go backend.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8080", changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    environmentOptions: {
      jsdom: { url: "http://localhost:3000/" },
    },
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
  },
});
