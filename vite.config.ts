import { defineConfig } from "vitest/config";

export default defineConfig({
  server: {
    host: "127.0.0.1",
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    strictPort: true,
  },
  build: {
    target: "es2022",
    sourcemap: false,
  },
  test: {
    environment: "node",
  },
});
